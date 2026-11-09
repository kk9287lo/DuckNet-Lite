"""
atomic_io.py — クラッシュ耐性のある永続化(原子書き込み+破損耐性読み込み)
====================================================================================
急な再起動・停止(電源断・kill・OS再起動)でも状態ファイルが壊れない/壊れても安全に
回復するための共有ヘルパ。プロジェクト各所で個別実装していた `tmp→os.replace` パターンを
1つに束ね、fsync による耐久性と破損時フォールバックを足す。

保証(正直な範囲):
  · **原子置換**: 一時ファイルに完全に書いてから os.replace で差し替える。読み手は常に
    『古い完全な版』か『新しい完全な版』のどちらかを見る(半端な版は見えない・同一FS前提)。
  · **耐久性**: 置換前に fsync(可能なら親ディレクトリも)。電源断の取りこぼしを最小化。
  · **破損耐性読み込み**: 壊れた JSON / 欠損 / 権限エラーでもクラッシュせず default を返す。
    本体が壊れていて .tmp が残っていれば .tmp からの回復も試みる。
限界: ネットワークFSや別FS跨ぎの replace は原子でない場合がある。バイト単位の完全な
電源断保証(ジャーナリング)まではしない=『壊さない・壊れても落ちない』を最大化する層。
"""
from __future__ import annotations

import errno
import json
import os
import stat
import tempfile
import threading
import time
import weakref
from typing import Any

_MAX_READ_BYTES = 64 * 1024 * 1024   # 状態JSONの読込上限(#111: 書込権限を持つ攻撃者が巨大
                                      # ファイルを置いてメモリ/CPUを浪費させる DoS を防ぐ)

# Windows の共有違反: Python の open() は FILE_SHARE_DELETE 無しで開くため、誰か(管理 API の
# 読み手・別プロセス・ウイルス対策/インデクサ)が開いている間は os.replace が、置換の最中は
# open が PermissionError になる。POSIX には無い一時的な失敗なので、Windows でだけ短い有界
# バックオフで再試行する(合計 約 0.43 秒で諦める)。POSIX の PermissionError は本物の権限
# 不足なので待たない。
# ただし要求経路では眠らない: ログを回せないときは上限で追記を拒否し、
# _ROTATE_RETRY_SEC 後に 1 回だけ試し直す。append_jsonl(wait=False) は開けなければ待たずに諦める。
# 読み手が tail している間、要求ごとに約 0.43 秒眠って要求処理が止まっていた。
_WIN = os.name == "nt"
_SHARE_RETRIES = 10
_ROTATE_RETRY_SEC = 5.0              # 回せなかったログは、この間ローテーションを試さない
_ROTATE_BLOCKED: dict = {}           # abspath -> 最後に回せなかった時刻(monotonic)
_APPEND_FILE_WAIT_SEC = 2.0         # admin audit の跨プロセス待機も有界


def _retry_sharing(fn, *args):
    if not _WIN:
        return fn(*args)
    delay = 0.002
    for _ in range(_SHARE_RETRIES - 1):
        try:
            return fn(*args)
        except PermissionError:
            time.sleep(delay)
            delay = min(delay * 2, 0.1)
    return fn(*args)


class LegacyStateSelectionRequired(OSError):
    """A default state path cannot be selected without an operator choice."""


_FOREIGN_ONLY_LOGS = ("sensor_log.jsonl", "decisions.jsonl", "txn_log.jsonl")
_LEGACY_SCAN_MAX_ENTRIES = 64


def _known_foreign_log_name(name: str) -> bool:
    for log in _FOREIGN_ONLY_LOGS:
        if name in (log, log + ".head", log + ".lock"):
            return True
        if name.startswith(log + ".") and name[len(log) + 1:].isdigit():
            return True  # bounded log rotations (.1, .2, ...), never arbitrary backups
    return False


def _legacy_state_needs_selection(path: str) -> bool:
    """Only known FalcoNet-only logs may be ignored when selecting a new home.

    Any old signing key, defense state, DuckNet audit log, unknown file, or
    unreadable/symlinked directory requires an explicit operator choice.  No
    legacy byte is read for migration or modified here.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if (not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0)
               & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            or os.path.islink(path)):
        return True
    try:
        with os.scandir(path) as entries:
            count = 0
            for entry in entries:
                count += 1
                if count > _LEGACY_SCAN_MAX_ENTRIES:
                    return True  # too much legacy content to classify safely at startup
                if (not _known_foreign_log_name(entry.name)
                        or not entry.is_file(follow_symlinks=False)
                        or getattr(entry.stat(follow_symlinks=False),
                                   "st_file_attributes", 0)
                           & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
                    return True
            return False
    except OSError:
        return True


def default_state_dir() -> str:
    """Select DuckNet's dedicated state home without importing ambiguous legacy state.

    FalcoNet used the former generic ~/.cache/dataplane default with the same
    signed filenames and key.  A fresh DuckNet chooses ~/.cache/ducknet-lite;
    an existing security/audit state at the old location requires an explicit
    DUCKNET_STATE_DIR choice so startup cannot silently drop or share BANs.
    """
    explicit = os.environ.get("DUCKNET_STATE_DIR")
    if explicit:
        return explicit
    cache = os.path.join(os.path.expanduser("~"), ".cache")
    legacy = os.path.join(cache, "dataplane")
    if _legacy_state_needs_selection(legacy):
        raise LegacyStateSelectionRequired(
            f"旧共用状態 {legacy} に判別不能な状態または記録が残っています。"
            "DuckNet-Lite と FalcoNet の所有元を判別できないため自動移行しません。"
            "DUCKNET_STATE_DIR に DuckNet-Lite 専用の保存先を明示してください。"
            "旧ファイルは変更していません。")
    dedicated = os.path.join(cache, "ducknet-lite")
    try:
        info = os.lstat(dedicated)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise LegacyStateSelectionRequired(
            "専用状態ディレクトリを検査できません。DUCKNET_STATE_DIR を明示してください。") from exc
    else:
        if (not stat.S_ISDIR(info.st_mode)
                or getattr(info, "st_file_attributes", 0)
                   & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                or os.path.islink(dedicated)):
            raise LegacyStateSelectionRequired(
                "専用状態ディレクトリが実ディレクトリではありません。"
                "DUCKNET_STATE_DIR に安全な保存先を明示してください。")
    return dedicated


def _sync_directory(path: str) -> bool | None:
    """True=durable sync, None=OS/FS unsupported, False=real I/O failure."""
    if os.name == "nt":
        return None                  # stdlib cannot open a Windows directory for fsync
    unsupported = {errno.EINVAL, errno.EBADF, errno.ENOSYS,
                   getattr(errno, "ENOTSUP", errno.EINVAL),
                   getattr(errno, "EOPNOTSUPP", errno.EINVAL)}
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        return None if exc.errno in unsupported else False
    try:
        try:
            os.fsync(fd)
            return True
        except OSError as exc:
            return None if exc.errno in unsupported else False
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def atomic_write_text(path: str, text: str, *, encoding: str = "utf-8",
                      errors: str = "strict", export_mode: int | None = None,
                      newline: str | None = None, status: dict | None = None) -> bool:
    """text を path へ原子的に書く。True は新ファイルの公開成功。
    status 指定時は published と durable(True/False/None=dir fsync非対応)を返す。
    rename 前の失敗では旧ファイルを保つ。rename 後の同期失敗は公開済みとして
    True を返し durable=False にする(呼出側のメモリだけを旧値へ戻さない)。
    一時ファイル名はランダム化し O_CREAT|O_EXCL で新規作成する(#111: 旧来の predictable な
    `path.tmp.<pid>` は、状態dirが(ステルス運用等で)共有/書込可能な場所を指す構成だと、
    攻撃者が先回りしてシンボリックリンクを置き『任意ファイル上書き』へ転用できた)。"""
    tmp = None
    published = False
    if status is not None:
        status.clear()
    try:
        d = os.path.dirname(path) or "."
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=d)
        with os.fdopen(fd, "w", encoding=encoding, errors=errors, newline=newline) as f:
            # 前衛への公開生成物だけ、既存の所有者/モードを保持する。秘密状態の
            # 通常の呼出しは mkstemp の 0600 を維持する。
            if export_mode is not None and os.name == "posix":
                import stat
                try:
                    previous = os.stat(path, follow_symlinks=False)
                except FileNotFoundError:
                    previous = None
                if previous is not None:
                    if not stat.S_ISREG(previous.st_mode):
                        raise ValueError("export target must be a regular file")
                    if (previous.st_uid != os.geteuid()
                            or stat.S_IMODE(previous.st_mode) & 0o022):
                        raise PermissionError("export target has an untrusted owner or writable mode")
                    current = os.fstat(f.fileno())
                    if (previous.st_uid, previous.st_gid) != (current.st_uid, current.st_gid):
                        os.fchown(f.fileno(), previous.st_uid, previous.st_gid)
                os.fchmod(f.fileno(), stat.S_IMODE(previous.st_mode) if previous else export_mode)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())          # 失敗時は公開せず元ファイルを残す
        # 永続化できないディレクトリは公開前に拒否する。rename 後にだけ試すと
        # dir fsync の実 I/O エラーを握り潰したまま成功と返していた。
        if _sync_directory(d) is False:
            return False
        _retry_sharing(os.replace, tmp, path)  # 原子置換(同一FS)。Windows の共有違反は待って再試行
        tmp = None
        published = True
        durable = _sync_directory(d)
        if status is not None:
            status.update(published=True, durable=durable)
        # 公開後の同期失敗を False にすると、呼出側がメモリを旧値へ戻す一方、
        # ディスクは新値のままになる。公開は成功とし、耐久性未確認を status に示す。
        return True
    except Exception:
        if status is not None:
            status.update(published=published, durable=False)
        return False
    finally:
        if status is not None and not status:
            status.update(published=False, durable=False)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except Exception:
                pass


def atomic_write_json(path: str, obj: Any, *, indent: int = 2,
                      status: dict | None = None) -> bool:
    """obj を読込上限内の JSON で原子的に公開する。status は text writer と同じ。"""
    try:
        text = json.dumps(obj, ensure_ascii=False, indent=indent)
        # 読み手は _MAX_READ_BYTES を超える JSON を拒否する。文字数ではなく、
        # backslashreplace を通した実出力の UTF-8 バイト数で公開前に判定する。
        # newline="" で Windows の LF→CRLF 変換も抑え、判定と実サイズを一致させる。
        if len(text.encode("utf-8", "backslashreplace")) > _MAX_READ_BYTES:
            if status is not None:
                status.clear()
                status.update(published=False, durable=False)
            return False
    except Exception:
        if status is not None:
            status.clear()
            status.update(published=False, durable=False)
        return False
    # backslashreplace: json.loads は '\udc80' のような孤立サロゲートをそのまま作るが、厳格な
    # UTF-8 では書けず保存が黙って失敗していた(管理 API で入った値 1 つで以後の保存が全滅)。
    # JSON 出力で UTF-8 に書けないのは文字列中の孤立サロゲートだけで、その \udXXX 表記は
    # JSON の正しいエスケープ=読み戻すと同じ値になる。それ以外の文字は従来どおり生で書く。
    return atomic_write_text(path, text, errors="backslashreplace", newline="",
                             status=status)


def safe_read_json(path: str, default: Any = None, *, strict: bool = False,
                   recover_tmp: bool = True, fail_on_io_error: bool = False) -> Any:
    """JSON を読む。壊れ/欠損/権限エラーでも例外を投げず default を返す。
    本体が壊れていて path.tmp が残っていれば、そこからの回復を試みる。
    署名付き状態では fail_on_io_error=True にして読取不能を欠損/破損から区別する。
    書込権限を持つ攻撃者が巨大ファイルを置いて読込側のメモリ/CPUを浪費させる DoS を
    防ぐため、_MAX_READ_BYTES を超えるファイルは壊れているものとして扱う(#111)。"""
    for candidate in ((path, path + ".tmp") if recover_tmp else (path,)):
        observed = False
        try:
            if fail_on_io_error:
                info = os.lstat(candidate)   # dangling symlink is present, never a missing main
                observed = True
                if not stat.S_ISREG(info.st_mode):
                    raise OSError("JSON source is not a regular file")
                size = info.st_size
            else:
                if not os.path.isfile(candidate):
                    continue
                size = os.path.getsize(candidate)
            if size > _MAX_READ_BYTES:
                continue
            # 置換の最中/他ハンドル保持中の一時的な共有違反(Windows)を『欠損』扱いしない
            # (署名付き状態が 'missing' に見えて既定値へ戻っていた)。
            if fail_on_io_error:
                identity = (info.st_dev, info.st_ino)
                return _retry_sharing(_load_json_file, candidate, strict, identity)
            return _retry_sharing(_load_json_file, candidate, strict)
        except FileNotFoundError:
            if fail_on_io_error and observed:
                raise                 # vanished after inspection: never trust a stale .tmp
            continue
        except OSError:
            if fail_on_io_error:
                raise
            continue
        except Exception:
            continue
    return default


def _load_json_file(p: str, strict: bool = False, expected_identity=None):
    # getsize() は早期除外だけ。サイズ確認後の追記/置換でも上限を超えて読まない。
    with open(p, "rb") as f:
        if expected_identity is not None:
            opened = os.fstat(f.fileno())
            if (opened.st_dev, opened.st_ino) != expected_identity:
                raise OSError("JSON source changed while opening")
        raw = f.read(_MAX_READ_BYTES + 1)
    if len(raw) > _MAX_READ_BYTES:
        raise ValueError("state JSON exceeds read limit")
    text = raw.decode("utf-8")
    if strict:
        # Declarative input is an authority, not a legacy state snapshot.
        # Duplicate members and non-finite numbers cannot have a unique
        # meaning across config managers and this process.
        from .saferegex import safe_json_loads
        invalid = object()
        parsed = safe_json_loads(text, max_len=_MAX_READ_BYTES, default=invalid,
                                 reject_duplicates=True, reject_nonfinite=True)
        if parsed is invalid:
            raise ValueError("invalid declarative JSON")
        return parsed
    return json.loads(text)


_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)   # POSIX: 最終要素が symlink なら失敗


def _rotate(path: str, backups: int) -> bool:
    """path → path.1 → … → path.{backups} と押し出し、最古は破棄。眠らない(要求経路から呼ばれる)。
    現行と押し出す最古の双方を退避し、全移動が成功した後だけ最古を削除する。
    中途失敗時は移動済み世代を逆順で戻す。戻しも失敗した場合は退避名を消さず残す。"""
    nonce = os.urandom(16).hex()
    staged = f"{path}.rot-current-{nonce}"
    retired = f"{path}.rot-retired-{nonce}"
    try:
        os.replace(path, staged)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    oldest = f"{path}.{backups}"
    oldest_staged = False
    moved = []
    try:
        if os.path.lexists(oldest):
            os.replace(oldest, retired)
            oldest_staged = True
        for i in range(backups, 1, -1):       # path.(i-1) → path.i
            src = f"{path}.{i - 1}"
            if os.path.lexists(src):
                dst = f"{path}.{i}"
                os.replace(src, dst)
                moved.append((src, dst))
        os.replace(staged, f"{path}.1")
    except OSError:
        # 一段でも戻せなければ以降の世代を上書きせず停止する。退避名に
        # 残した行は、障害後の回収に使えるので cleanup しない。
        restored = True
        for src, dst in reversed(moved):
            try:
                os.replace(dst, src)
            except OSError:
                restored = False
                break
        if restored and oldest_staged:
            try:
                os.replace(retired, oldest)
            except OSError:
                pass
        try:
            os.replace(staged, path)
        except OSError:
            pass
        return False
    if oldest_staged:
        try:
            os.unlink(retired)                   # 成功したローテーションだけ最古を破棄
        except OSError:
            pass                                # 余分な退避は残しても行を失わない
    return True


def _complete_jsonl_tail(fd: int) -> bool:
    """A failed short-write rollback must not be joined to a later audit row."""
    size = os.fstat(fd).st_size
    if not size:
        return True
    os.lseek(fd, -1, os.SEEK_END)
    return os.read(fd, 1) == b"\n"


def append_jsonl(path: str, obj: Any, *, max_bytes: int = 5_000_000,
                 backups: int = 1, encoding: str = "utf-8", wait: bool = True) -> bool:
    """1行 JSON を追記する。追記後にサイズ上限を超えそうなら先にローテーションする。
    追記ログ(監査ログ)の無制限肥大を防ぐ共有ヘルパ。失敗しても例外は投げない。
    ローテーションは眠らない: 読み手が握っていれば上限で追記を拒否し、
    _ROTATE_RETRY_SEC 後の追記で 1 回だけ試し直す。
    wait=False は要求経路(イベントループ・接続処理)用: Windows の共有違反で開けなくても待たずに
    諦める(False)。既定の wait=True は管理操作の監査など、短く待ってでも行を残したい書き手用。"""
    try:
        line = json.dumps(obj, ensure_ascii=False) + "\n"
        # Preserve the platform's existing JSONL newline convention. Count
        # the actual encoded bytes (including Windows CRLF) and the
        # backslash escapes used for lone surrogates before reserving space.
        wire_line = line.replace("\n", os.linesep).encode(
            encoding, "backslashreplace")
        line_bytes = len(wire_line)
        if type(max_bytes) is not int or max_bytes <= 0 or line_bytes > max_bytes:
            return False
    except Exception:
        return False
    try:
        d = os.path.dirname(path) or "."
        os.makedirs(d, mode=0o700, exist_ok=True)
        # 同一プロセスの複数スレッド(ThreadingHTTPServer の管理 API 等)がローテーションを
        # 同時に走らせると、押し出し(.1→.2 …)が交錯して世代ファイルを上書きし行が消えていた。
        # サイズ判定〜ローテーション〜追記をパス単位で直列化する。
        # Nonwaiting diagnostics must not queue behind either mutex. Filesystem
        # calls are still synchronous; event-loop callers must offload them.
        deadline = time.monotonic() + _APPEND_FILE_WAIT_SEC if wait else None
        lock = _append_lock(path, wait=wait, deadline=deadline)
        if lock is None:
            return False
        if wait:
            remaining_wait = deadline - time.monotonic()
            if remaining_wait <= 0 or not lock.acquire(timeout=remaining_wait):
                return False
        elif not lock.acquire(blocking=False):
            return False
        try:
            file_lock = _append_file_lock(path, wait=wait, deadline=deadline)
            if file_lock is None:
                return False
            try:
                try:
                    cur = os.path.getsize(path)
                except FileNotFoundError:
                    cur = 0
                except OSError:
                    # If an existing log cannot be sized, its remaining
                    # capacity is unknown. Append-only access is insufficient.
                    return False
                if cur + line_bytes > max_bytes:
                    # Check before rotating: a torn active row must not be
                    # hidden in a backup while this append reports success.
                    try:
                        if os.path.islink(path):
                            return False
                        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW
                                     | getattr(os, "O_BINARY", 0))
                        try:
                            if os.fstat(fd).st_size != cur or not _complete_jsonl_tail(fd):
                                return False
                        finally:
                            os.close(fd)
                    except OSError:
                        return False
                    key = os.path.abspath(path)
                    now = time.monotonic()
                    last = _ROTATE_BLOCKED.get(key)
                    if last is None or now - last >= _ROTATE_RETRY_SEC:
                        if _rotate(path, max(1, backups)):
                            _ROTATE_BLOCKED.pop(key, None)
                        else:
                            _ROTATE_BLOCKED[key] = now
                            return False
                    else:
                        # A held reader must not turn the retry interval into
                        # unbounded log growth.
                        return False
                opened = (_retry_sharing(_open_append_nofollow, path, encoding) if wait
                          else _open_append_nofollow(path, encoding))
                with opened as f:
                    # Capture the post-rotation size, not the old generation's
                    # size. A short disk write must not leave a JSONL fragment
                    # which a later successful append joins into a bad row.
                    before = os.fstat(f.fileno()).st_size
                    if before + line_bytes > max_bytes or not _complete_jsonl_tail(f.fileno()):
                        return False
                    try:
                        remaining = memoryview(wire_line)
                        while remaining:
                            written = f.write(remaining)
                            if written is None or written <= 0:
                                raise OSError("short JSONL append")
                            remaining = remaining[written:]
                    except BaseException:
                        # Binary/unbuffered output cannot flush a hidden suffix
                        # after this rollback. Shrinking is normally possible
                        # even when the original write failed with ENOSPC.
                        try:
                            os.ftruncate(f.fileno(), before)
                        except OSError:
                            pass
                        raise
            finally:
                _release_append_file_lock(file_lock)
        finally:
            lock.release()
        return True
    except Exception:
        return False


class _AppendLock:
    """Weak-referenceable mutex with the existing acquire/release interface."""

    __slots__ = ("lock", "__weakref__")

    def __init__(self):
        self.lock = threading.Lock()

    def acquire(self, *args, **kwargs):
        return self.lock.acquire(*args, **kwargs)

    def release(self):
        self.lock.release()


# append_jsonl and any waiting caller retain the holder until after release.
_APPEND_LOCKS = weakref.WeakValueDictionary()
_APPEND_LOCKS_GUARD = threading.Lock()


def _append_lock(path: str, *, wait: bool = True, deadline=None):
    key = os.path.abspath(path)
    if wait and deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not _APPEND_LOCKS_GUARD.acquire(timeout=remaining):
            return None
    elif not _APPEND_LOCKS_GUARD.acquire(blocking=wait):
        return None
    try:
        holder = _APPEND_LOCKS.get(key)
        if holder is None:
            holder = _AppendLock()
            _APPEND_LOCKS[key] = holder
        return holder
    finally:
        _APPEND_LOCKS_GUARD.release()


def _append_file_lock(path: str, *, wait: bool, deadline):
    """Serialize size, rotation and append across cluster worker processes.

    A thread-only lock lets two workers both observe spare capacity and append
    past the bound, or interleave generation renames. A separate lock file is
    retained; OS locks are released automatically if a worker exits.
    """
    lock_path = path + ".append.lock"
    fd = None
    try:
        if os.path.islink(lock_path):
            return None
        flags = (os.O_RDWR | os.O_CREAT | _O_NOFOLLOW
                 | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_CLOEXEC", 0)
                 | getattr(os, "O_NOINHERIT", 0)
                 | getattr(os, "O_BINARY", 0))
        fd = os.open(lock_path, flags, 0o600)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None
    except OSError:
        if fd is not None:
            os.close(fd)
        return None
    if wait and time.monotonic() >= deadline:
        os.close(fd)
        return None
    while True:
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except OSError as exc:
            if (not wait or time.monotonic() >= deadline
                    or exc.errno not in (errno.EACCES, errno.EAGAIN,
                                         getattr(errno, "EWOULDBLOCK", errno.EAGAIN))):
                os.close(fd)
                return None
            time.sleep(0.005)
        except (ImportError, AttributeError):
            os.close(fd)
            return None


def _release_append_file_lock(fd: int) -> None:
    try:
        if os.name == "nt":
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_UN)
    except (OSError, ImportError, AttributeError):
        pass  # close releases the OS lock even if explicit unlock failed
    finally:
        os.close(fd)


def _open_append_nofollow(path: str, encoding: str):
    """追記用に symlink を経由せず開く(#symlink-arbitrary-write)。
    共有ディレクトリに置かれる監査ログを攻撃者が任意ファイルへの symlink に差し替えると、
    素の open(path, "a") はそれを追従してしまい、ログ行の注入や対象ファイルの肥大を許す。
    予め symlink を除去し(追従しない)、POSIX では O_NOFOLLOW でも最終要素の追従を拒否する。"""
    try:
        if os.path.islink(path):
            os.unlink(path)
    except OSError:
        pass
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND | _O_NOFOLLOW
                 | getattr(os, "O_BINARY", 0), 0o600)
    # The caller pre-encodes the complete JSONL row with backslashreplace and
    # platform newlines. Unbuffered binary output permits exact short-write
    # accounting and rollback before the file descriptor is closed.
    return os.fdopen(fd, "a+b", buffering=0)


_TAIL_AVG_LINE = 512   # 末尾読みの初期見積り(1行あたりバイト数)
_TAIL_MAX_ROUNDS = 6   # 見積りが外れた時の読み直し上限(有界化)


def tail_jsonl(path: str, n: int = 50, *, strict: bool = False,
               max_bytes: int | None = None) -> list:
    """JSONL ファイル末尾の最大 n 行を新しい順(末尾=最新が先頭)で読む。
    既定は欠損/壊れ行を飛ばす従来のテレメトリ用読み方。監査履歴は strict=True で
    読込失敗・壊れた末尾を空の正常履歴に変えず、呼び出し元へ例外を返す。"""
    try:
        if strict:
            try:
                target = os.lstat(path)
            except FileNotFoundError:
                return []
            if not stat.S_ISREG(target.st_mode):
                raise OSError("JSONL source is not a regular file")
            if max_bytes is not None and (type(max_bytes) is not int or max_bytes < 0):
                raise ValueError("invalid JSONL read limit")
        elif not os.path.isfile(path):
            return []
        n = max(1, n)
        # 末尾 n 行が欲しいだけなのに readlines() でファイル全体を読み込んでいた。
        # 管理画面がポーリングで叩くため、ログが育つほど 1 回の読み取り量が増える
        # (= 蓄積量 x ポーリング回数)。末尾から必要なぶんだけ遡って読む。
        want = n * _TAIL_AVG_LINE
        with _retry_sharing(open, path, "rb") as f:
            if strict:
                opened = os.fstat(f.fileno())
                if (not stat.S_ISREG(opened.st_mode) or
                        (opened.st_dev, opened.st_ino) !=
                        (target.st_dev, target.st_ino)):
                    raise OSError("JSONL source changed while opening")
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if strict:
                if max_bytes is not None and size > max_bytes:
                    raise ValueError("JSONL source exceeds read limit")
                if size:
                    f.seek(-1, os.SEEK_END)
                    if f.read(1) != b"\n":
                        raise ValueError("unterminated JSONL row")
            for _ in range(_TAIL_MAX_ROUNDS):
                start = max(0, size - want)
                f.seek(start)
                raw = f.read(size - start)
                # 行区切りは *バイトの* \n だけ。str.splitlines() は U+0085/U+2028/U+2029 でも
                # 割るため、それを含む記録(latin-1 で読んだ UA の 0x85 等)が 2 つの壊れた断片に
                # なって捨てられ、管理画面から消えていた(ログ回避)。UTF-8 の多バイト文字は
                # 0x0A を含まないので、復号前に割っても文字は壊れない。
                lines = [ln.decode("utf-8", "strict" if strict else "replace")
                         for ln in raw.split(b"\n")]
                if lines and not lines[-1].strip():
                    lines.pop()                 # 末尾の改行が作る空要素(splitlines と同じ数え方)
                if start > 0:
                    lines = lines[1:]           # 先頭は途中で切れている可能性がある
                if len(lines) >= n or start == 0:
                    break
                want *= 4                       # 行が長かった=範囲を広げて読み直す
            if strict and start > 0 and len(lines) < n:
                raise ValueError("JSONL tail scan incomplete")
        lines = lines[-n:]
    except Exception:
        if strict:
            raise
        return []
    out = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            if strict:
                raise ValueError("empty JSONL row")
            continue
        try:
            if strict:
                def unique_pairs(pairs):
                    values = {}
                    for key, value in pairs:
                        if key in values:
                            raise ValueError("duplicate JSONL key")
                        values[key] = value
                    return values

                def reject_constant(_value):
                    raise ValueError("nonfinite JSONL number")

                out.append(json.loads(line, object_pairs_hook=unique_pairs,
                                      parse_constant=reject_constant))
            else:
                out.append(json.loads(line))
        except Exception:
            if strict:
                raise ValueError("invalid JSONL row") from None
            continue
    return out


def safe_read_text(path: str, default: str = "") -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return default
