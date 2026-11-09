"""
signed_state.py — 可変状態ファイルの改竄耐性(HMAC署名・標準ライブラリのみ・依存ゼロ)
====================================================================================
BAN リスト・カスタム署名・設定・IoC のような *常時変化する* 状態は固定ハッシュにできない。
本モジュールはそれらを **保存時に HMAC 署名・読込時に検証** して守る。攻撃者がホスト上で
blocklist.json を書き換えて自分を unban したり、rules.json を空にして検知を無効化しても、
署名が一致しないため『改竄』として弾き、安全側デフォルトへフェイルセーフする。

形式: 1ファイル原子書き込みのまま、ペイロードを署名エンベロープで包む:
    {"_sv": 1, "_sig": "<hmac-sha256 hex>", "_payload": <元のオブジェクト>}
署名は payload の正準JSON(キー順安定)に対する HMAC-SHA256。読込は (status, value) を返す:
  · "ok"       … 署名検証成功。value=payload。
  · "tampered" … 署名不一致/エンベロープ破損 → value=default(呼び出し側がフェイルセーフ)。
  · "unsigned" … 旧来の無署名プレーンファイル → value=生オブジェクト(呼び出し側が再保存で移行)。
  · "missing"  … 本体が欠損 → value=default。読取不能は "tampered"。

鍵は再起動を跨ぐ必要があるため永続化する(env 推奨、無ければ state_dir に 0600 で生成保存)。
正直な信頼境界: 鍵が状態ファイルと同じディスクにある場合、root 攻撃者は鍵も読めて再署名し得る
=完全な保護には外部鍵(env/HSM/別権限)が要る。env DUCKNET_STATE_KEY 指定でその水準へ上げられる。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
import threading
import time
import weakref
from contextlib import contextmanager

from .atomic_io import atomic_write_json, safe_read_json, _sync_directory

# ロールバック攻撃対策(#102): プロセス生存中に受理した最大バージョン(path 毎)。攻撃者が
# 『古い正署名ファイル』で巻き戻しても、稼働中はメモリ高水位が古い版を拒否する。再起動跨ぎは
# サイドカーの .hw ファイル(同じく署名)で補強する。正直な残余: ディスク全書込み権限+.hw の
# 存在を知る高度攻撃者が *両方* を整合的に巻き戻せば突破し得る(完全防止には外部単調カウンタ要)。
_MEM_HW: dict = {}
_MEM_MIN_SV: dict = {}       # このプロセスで受理/保存した目的束縛付き形式の下限


class _PathLock:
    # A holder is weak-referenceable on every supported Python runtime,
    # regardless of whether its native lock object supports weak references.
    __slots__ = ("lock", "__weakref__")

    def __init__(self):
        self.lock = threading.Lock()


# The guard's local holder keeps the lock alive while held or waited on.
# Completed temporary state directories must not retain Windows lock handles.
_PATH_LOCKS = weakref.WeakValueDictionary()
_PATH_LOCKS_GUARD = threading.Lock()
_LOCK_WAIT_SEC = 2.0        # 状態の競合で要求/起動を無期限に待たせない
MISSING_FINGERPRINT = ""   # CAS: ファイルも署名済み高水位も無い初回状態
MISSING_WITH_HISTORY_FINGERPRINT = "missing-with-history"  # 正署名 .hw を残す本体欠損

# Windows は os.open() に O_BINARY を渡さないと既定でテキストモード(0x0A→0x0D0x0A変換)になり、
# 生のバイト列(鍵)を破損させる。POSIX には無い属性なので getattr で安全に0フォールバック。
_O_BIN = getattr(os, "O_BINARY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)   # POSIX: 最終要素が symlink なら open 失敗。Win は無し。


def _require_private_state_dir(state_dir: str, *, create: bool = True) -> None:
    """POSIX の状態保存先を同じ UID 所有・他 UID 書込不可に限定する。

    既存の他者書込可能な場所は、旧形式ファイルを植えられた可能性があるので chmod で
    信頼済みに変えず拒否する。root 所有 sticky /tmp は子を他 UID が置換できない。
    """
    if not state_dir:
        raise OSError("state directory is empty")
    if create:
        os.makedirs(state_dir, mode=0o700, exist_ok=True)
    if os.name != "posix":
        return
    uid = os.geteuid()
    target = os.path.abspath(state_dir)
    if target == os.path.abspath(os.sep):
        raise OSError("filesystem root cannot be used as state directory")

    def components(path):
        parts = []
        while True:
            parts.append(path)
            parent = os.path.dirname(path)
            if parent == path:
                return reversed(parts)
            path = parent

    # 元のパスと symlink 解決後のパスを両方検査する。祖先の symlink は
    # root/現 UID 管理なら許容し、最終ディレクトリの symlink は拒否する。
    for chain in (target, os.path.realpath(target)):
        for part in components(chain):
            st = os.lstat(part)
            if stat.S_ISLNK(st.st_mode):
                if part == target or st.st_uid not in (0, uid):
                    raise OSError(f"untrusted state directory link: {part}")
                continue
            if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, uid):
                raise OSError(f"untrusted state directory owner: {part}")
            if st.st_mode & 0o022:
                if part == target or not (st.st_uid == 0 and st.st_mode & stat.S_ISVTX):
                    raise OSError(f"state directory is writable by others: {part}")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _O_NOFOLLOW
    fd = os.open(target, flags)
    try:
        fst = os.fstat(fd)
        if not stat.S_ISDIR(fst.st_mode) or fst.st_uid != uid or fst.st_mode & 0o022:
            raise OSError(f"state directory is not private: {target}")
        current = os.lstat(target)
        if ((current.st_dev, current.st_ino) != (fst.st_dev, fst.st_ino)
                or not stat.S_ISDIR(current.st_mode)):
            raise OSError(f"state directory changed while checking: {target}")
    finally:
        os.close(fd)


@contextmanager
def _state_guard(path: str):
    """同一状態の本体・高水位をプロセス/スレッド間で一組として扱う。有界待機。"""
    key = os.path.abspath(path)
    # The table mutex, path mutex and OS file lock share one deadline. A
    # stalled thread holding the table mutex must not bypass the advertised
    # state-lock timeout before we even reach the per-path lock.
    deadline = time.monotonic() + _LOCK_WAIT_SEC
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not _PATH_LOCKS_GUARD.acquire(timeout=remaining):
        yield False
        return
    try:
        holder = _PATH_LOCKS.get(key)
        if holder is None:
            holder = _PathLock()
            _PATH_LOCKS[key] = holder
    finally:
        _PATH_LOCKS_GUARD.release()
    lock = holder.lock
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not lock.acquire(timeout=remaining):
        yield False
        return
    fd = None
    file_locked = False
    try:
        try:
            _require_private_state_dir(os.path.dirname(path) or ".", create=False)
            fd = os.open(path + ".lock", os.O_RDWR | os.O_CREAT | _O_BIN | _O_NOFOLLOW, 0o600)
            # A slow filesystem open can consume the entire shared budget.
            # Do not turn an immediately available OS lock into a late commit.
            while time.monotonic() < deadline:
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    file_locked = True
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.01)
        except OSError:
            pass
        # The nonblocking lock call itself can finish after the deadline.
        # Retain file_locked for finally/unlock, but deny publication.
        yield file_locked and time.monotonic() < deadline
    finally:
        if file_locked and fd is not None:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                if os.name == "nt":
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        try:
            if fd is not None:
                os.close(fd)
        finally:
            lock.release()


def _read_key_file(key_path: str):
    """鍵ファイルを *symlink 追従せず・通常ファイルのみ* 読む(#symlink-key)。返り値 bytes/None。
    共有 state_dir で攻撃者が .statekey を既知内容ファイルへの symlink にすり替え、その内容を
    HMAC 鍵として読ませ、鍵既知 → 署名済み状態(BAN/設定/署名)を偽造する攻撃を封じる。
    0600 が実効的でない Windows では O_NOFOLLOW が無いため lstat の symlink 判定で補う。"""
    import stat as _stat
    try:
        st = os.lstat(key_path)
        if not _stat.S_ISREG(st.st_mode):
            return None                       # symlink/FIFO 等は open 前に拒否(ブロック回避)
        # lstat 後に通常ファイルを FIFO へ置換されても、open 自体で待ち続けない。
        # 通常ファイルでは O_NONBLOCK は無害。fstat で実際に開いた型を再確認する。
        fd = os.open(key_path, os.O_RDONLY | _O_BIN | _O_NOFOLLOW
                     | getattr(os, "O_NONBLOCK", 0))
        try:
            fst = os.fstat(fd)
            if not _stat.S_ISREG(fst.st_mode):
                return None                   # 通常ファイル以外(FIFO/デバイス/ディレクトリ等)は拒否
            if os.name == "posix":
                # 所有者と権限も確かめる。共有 state_dir に *他ユーザーが作った* 鍵を読むと、
                # 攻撃者の知っている鍵で「署名は正しい」と判定してしまい、署名済み状態
                # (BAN/設定)の偽造を検出できなくなる。他人所有は拒否。
                if fst.st_uid != os.geteuid():
                    return None
                if fst.st_mode & 0o077:
                    # group/other から読める=鍵が漏れうる。ただしここで *拒否* すると、
                    # 既存インストール(緩い権限で作られた鍵)では読めない→O_EXCL は
                    # FileExistsError→永続化されない一時鍵を返す、という経路に落ちて
                    # 起動のたびに鍵が変わり、自分が署名した BAN/設定を自分で検証できず
                    # 既定値へ黙って戻ってしまう。自分の物なら締め直して読む(自己修復)。
                    try:
                        os.fchmod(fd, 0o600)
                    except OSError:
                        return None       # 締められない=保護できないので使わない
            data = os.read(fd, 1 << 16)
            return data if len(data) == 32 else (b"" if not data else None)
        finally:
            os.close(fd)
    except Exception:
        return None


def persistent_key(state_dir: str, env_var: str = "DUCKNET_STATE_KEY",
                   filename: str = ".statekey") -> bytes:
    """状態署名用の永続鍵。env_var があればそれを使う(最も安全=外部鍵)。無ければ
    state_dir/filename を 0600 で生成保存して再利用する(再起動を跨いで検証できるように)。
    生成は 0600 の一時ファイルに書き切ってから排他的に公開する(#111: 旧来の open→chmod は、
    作成〜権限設定の間に他ユーザーから読める窓があった。排他作成は他プロセスとの初回生成
    競合も検出し、その場合は相手が書いた鍵を読む。詳細は load_or_create_key)。
    Windows は os.chmod が実効的なACL制限にならない点に注意(ファイル属性のみ)=真に外部から
    守るには env_var を使うこと。"""
    _require_private_state_dir(state_dir)
    if env_var in os.environ:
        env = os.environ[env_var]
        if not env:
            raise OSError(f"{env_var} is explicitly empty")
        try:
            external_key = env.encode("utf-8")
        except UnicodeError as exc:
            raise OSError(f"{env_var} is not valid UTF-8 text") from exc
        if len(external_key) < 32:
            raise OSError(
                f"{env_var} needs at least 32 UTF-8 bytes from a random secret; "
                "stop the gateway and migrate any state signed with a shorter "
                "external key offline before rotating it")
        return external_key
    return load_or_create_key(os.path.join(state_dir, filename))


# 0 バイトの鍵ファイルがこれより古ければ『他プロセスが作成直後で書込中』ではなく、旧版が
# 作成〜書込の間でクラッシュ/ENOSPC した残骸とみなす。
_EMPTY_KEY_STALE_SEC = 2.0


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        if n <= 0:
            raise OSError(28, "short write")      # ENOSPC 相当
        view = view[n:]


def _write_key_tmp(d: str, k: bytes) -> str:
    """同じディレクトリの mkstemp(0600・O_EXCL・Windows は O_BINARY)へ鍵を全部書いて
    fsync した一時ファイルのパスを返す。失敗したら一時ファイルは残さない。"""
    fd, tmp = tempfile.mkstemp(prefix=".key.", dir=d)
    try:
        try:
            _write_all(fd, k)
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return tmp


def _create_key_file(key_path: str, k: bytes) -> None:
    """鍵ファイルを『全部書けた時だけ名前が現れる』形で新規作成する(既存なら FileExistsError)。
    旧実装は O_CREAT|O_EXCL で名前を先に作ってから書いていたため、書込失敗(ENOSPC)や電源断で
    0 バイトの鍵が残り、以後の起動は毎回『空=鍵なし→新しい一時鍵』に落ちて、前回署名した
    状態がすべて改竄扱いで初期化され続けた。完成済みの一時ファイルを os.link で排他的に
    公開する(リンクは既存名を上書きしない=初回生成の競合も従来どおり検出できる)。"""
    d = os.path.dirname(key_path) or "."
    tmp = _write_key_tmp(d, k)
    try:
        try:
            os.link(tmp, key_path)
        except FileExistsError:
            raise
        except (OSError, AttributeError, NotImplementedError):
            pass                                  # ハードリンク非対応の FS(FAT 等)→ 下へ
        else:
            if _sync_directory(d) is False:
                raise OSError("state key directory sync failed")
            return
        fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | _O_BIN, 0o600)
        try:
            try:
                _write_all(fd, k)
                os.fsync(fd)
            finally:
                os.close(fd)
        except BaseException:
            try:
                os.unlink(key_path)               # 空/半端な鍵を残さない(次回起動で作り直せる)
            except OSError:
                pass
            raise
        if _sync_directory(d) is False:
            raise OSError("state key directory sync failed")
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _replace_stale_empty_key(key_path: str, k: bytes) -> bool:
    """旧版が残した 0 バイトの鍵ファイルを k で原子的に置き換える。作成直後(書込中かもしれない)
    の空ファイルには触らない。置き換えたら True。"""
    import stat as _stat
    try:
        st = os.lstat(key_path)
        if not _stat.S_ISREG(st.st_mode) or st.st_size != 0:
            return False
        if abs(time.time() - st.st_mtime) < _EMPTY_KEY_STALE_SEC:
            return False
        tmp = _write_key_tmp(os.path.dirname(key_path) or ".", k)
        try:
            os.replace(tmp, key_path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        if _sync_directory(os.path.dirname(key_path) or ".") is False:
            raise OSError("state key directory sync failed")
        return True
    except Exception:
        return False


def load_or_create_key(key_path: str) -> bytes:
    """鍵ファイルを読む。無ければ 32 バイトの乱数鍵を生成して永続化する。永続化できなかった
    場合は起動を止める。一時鍵で署名すると再起動後に全状態を検証できなくなる。"""
    _require_private_state_dir(os.path.dirname(key_path) or ".")
    k0 = _read_key_file(key_path)             # symlink 非追従・通常ファイルのみ(#symlink-key)
    if k0:
        if _sync_directory(os.path.dirname(key_path) or ".") is False:
            raise OSError(f"state key directory sync failed: {key_path}")
        return k0
    # 欠損/空鍵の生成と旧版残骸の置換を跨プロセスで一組にする。旧版は stale 0-byte
    # を見た2プロセスが別鍵で順に os.replace でき、一方が署名した状態を他方が
    # 直後に読めなくしていた。lock 後の再読込で先着の完成鍵を必ず採る。
    with _state_guard(key_path) as locked:
        if not locked:
            raise OSError(f"state key lock is unavailable: {key_path}")
        k0 = _read_key_file(key_path)
        if k0:
            if _sync_directory(os.path.dirname(key_path) or ".") is False:
                raise OSError(f"state key directory sync failed: {key_path}")
            return k0
        import secrets as _s
        k = _s.token_bytes(32)
        try:
            os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
            _create_key_file(key_path, k)
        except FileExistsError:
            # ロックを知らない旧版プロセスとの初回生成競合は従来のリトライで吸収。
            k2 = None
            for _attempt in range(5):
                k2 = _read_key_file(key_path)
                if k2:
                    return k2
                time.sleep(0.01 * (_attempt + 1))
            if k2 == b"":
                if not _replace_stale_empty_key(key_path, k):
                    raise OSError(f"state key repair failed: {key_path}")
                k3 = _read_key_file(key_path)
                if k3:
                    return k3
        except OSError as exc:
            raise OSError(f"state key is not durable: {key_path}") from exc
        except Exception as exc:
            raise OSError(f"state key is unavailable: {key_path}") from exc
        verified = _read_key_file(key_path)
        if verified != k:
            raise OSError(f"state key could not be verified: {key_path}")
        return k


def _canon(obj) -> bytes:
    """署名対象の正準バイト列(キー順安定=再シリアライズで署名が揺れない)。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8", "backslashreplace")


def payload_fingerprint(obj) -> str:
    """署名対象の生 payload を鍵に依存しない SHA-256 で識別する(CAS 基準)。"""
    return hashlib.sha256(_canon(obj)).hexdigest()


def sign_payload(obj, key: bytes) -> str:
    return hmac.new(key, _canon(obj), hashlib.sha256).hexdigest()


def _sig_eq(expected: str, sig) -> bool:
    """署名(hex)の定数時間比較。hmac.compare_digest は非 ASCII の str で TypeError を投げる
    ため、攻撃者が "_sig": "é" や非文字列を置くと『例外は投げない』はずの読込から例外が漏れ、
    NetShield の起動や以後の保存が丸ごと落ちていた。正規の署名は常に ASCII の hex 文字列
    なので、それ以外は比較せず不一致(=改竄)とする。"""
    return isinstance(sig, str) and sig.isascii() and bool(sig) \
        and hmac.compare_digest(expected, sig)


def _int_or(v, default: int = 0) -> int:
    """int() 変換。JSON の Infinity/NaN(OverflowError/ValueError)や型違いは default。"""
    try:
        return int(v)
    except (TypeError, ValueError, OverflowError):
        return default


def verify_payload(obj, sig: str, key: bytes) -> bool:
    return _sig_eq(sign_payload(obj, key), sig)


def _hw_path(path: str) -> str:
    return path + ".hw"


def _read_file_hw_meta(path: str, key: bytes) -> tuple[int, int, bool]:
    """サイドカー .hw(署名済みの最大バージョン)を読む。検証失敗/欠損は 0。
    署名対象に *対象ファイルの basename* を含める(本体エンベロープの purpose 束縛と同じ考え)。
    以前は {"_ver": n} だけに署名していたため、ある state の .hw を別の state の .hw として
    そのまま置ける=低いバージョンの .hw を移植して高水位を下げ、ロールバック防止を無効化
    できた。束縛が無い旧形式は受理しない(0 扱い)=移植を将来にわたって無効化する。
    旧形式からの移行時は高水位が一度 0 に戻るが、メモリ高水位(_MEM_HW)と ms 由来の
    単調バージョンが働き、次回書込みで束縛付き .hw に置き換わる。"""
    # An invalid present .hw is evidence of tampering. Do not silently recover
    # from a stale .hw.tmp: that could lower the trusted version on restart.
    raw = safe_read_json(_hw_path(path), None, recover_tmp=False)
    if isinstance(raw, dict):
        ver = _int_or(raw.get("_ver", 0))
        minimum = _int_or(raw.get("_min_sv"), -1) if "_min_sv" in raw else 0
        if ver > 0 and minimum >= 0 and verify_payload(
                _hw_payload(path, ver, minimum if "_min_sv" in raw else None),
                raw.get("_sig", ""), key):
            return ver, minimum, True
    return 0, 0, False


def _read_file_hw(path: str, key: bytes) -> int:
    return _read_file_hw_meta(path, key)[0]


def _path_presence(path: str) -> bool | None:
    """True=present, False=absent, None=metadata unavailable (never pristine)."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return None
    return True


def _read_signed_candidate(path: str):
    """Read one signed generation without replacing a damaged main with .tmp.

    A temporary file is crash recovery only when the main pathname was truly
    absent.  A present but corrupt main is untrusted even if an older valid
    temporary copy survives.  Remember presence before reading so a pathname
    that disappears during the read cannot become a clean first boot.
    """
    present = _path_presence(path)
    if present is None:
        raise OSError("signed state main cannot be inspected")
    if present:
        return safe_read_json(path, None, recover_tmp=False,
                              fail_on_io_error=True), True
    temp = path + ".tmp"
    temp_present = _path_presence(temp)
    if temp_present is None:
        raise OSError("signed state temporary file cannot be inspected")
    if not temp_present:
        if _path_presence(path) is not False:
            raise OSError("signed state main appeared during recovery")
        return None, False
    raw = safe_read_json(temp, None, recover_tmp=False,
                         fail_on_io_error=True)
    if _path_presence(path) is not False:
        raise OSError("signed state main appeared during recovery")
    return raw, True


def has_signed_history(path: str, key: bytes) -> bool:
    """署名済み高水位またはその破損した痕跡が残るか。

    存在するが署名不正の .hw を『初回起動』と扱うと、main と marker を消すだけで
    ACL/BAN が無警告で初期化される。完全に全痕跡を消す攻撃の区別には外部状態が要る。
    """
    return bool(_MEM_HW.get(path, 0) or _path_presence(_hw_path(path)) is not False)


def _hw_payload(path: str, ver, min_sv: int | None = None) -> dict:
    """.hw の署名対象。basename で束縛して別 state への移植を無効化する。"""
    payload = {"_hw": 1, "_ver": _int_or(ver), "_for": os.path.basename(path)}
    if min_sv is not None:
        payload["_min_sv"] = int(min_sv)
    return payload


def _write_file_hw(path: str, ver: int, key: bytes, min_sv: int = 3,
                   status_out: dict | None = None) -> bool:
    env = {"_ver": int(ver), "_min_sv": min_sv,
           "_sig": sign_payload(_hw_payload(path, ver, min_sv), key)}
    try:
        status = {}
        written = atomic_write_json(_hw_path(path), env, indent=0, status=status)
        if status_out is not None:
            status_out.clear()
            status_out.update(published=status.get("published", bool(written)),
                              durable=status.get("durable", True if written else False))
        return bool(written and status.get("durable", True) is not False)
    except Exception:
        if status_out is not None:
            status_out.clear()
            status_out.update(published=False, durable=False)
        return False


def _next_version(path: str, prev_hint: int = 0, hw_floor: int = 0) -> int:
    """時刻・前回版・検証済みディスク高水位を超える次の版を返す。
    prev_hint>0(=このプロセスが既に書いた版)を渡せば本体を読まない: 旧実装は保存の
    たびに対象ファイルを全文読み直して JSON 解析しており、状態が育つほど 1 保存あたりの
    固定費が増えていた(実測 3.2MB で 21.9ms/保存)。初回だけディスクから拾えば十分。"""
    prev = max(_int_or(prev_hint or 0), _int_or(hw_floor or 0))
    if prev <= 0:
        raw = safe_read_json(path, None)
        if isinstance(raw, dict):
            prev = _int_or(raw.get("_ver", 0))     # Infinity 等で保存が永久に落ちないように
    return max(prev + 1, int(time.time() * 1000))


_UNREAD = object()


def _cas_fingerprint_locked(path: str, key: bytes) -> str | None:
    """main と .hw を副作用なく検証し、現行 payload の指紋を返す。None=不明/改竄。"""
    hw_present = _path_presence(_hw_path(path))
    if hw_present is None:
        return None
    try:
        raw, observed = _read_signed_candidate(path)
    except OSError:
        return None
    floor, _min_sv, had_hw = _read_file_hw_meta(path, key)
    if hw_present and not had_hw:
        return None                         # 壊れた高水位を CAS で黙って上書きしない
    floor = max(floor, _MEM_HW.get(path, 0))
    if raw is None:
        # 欠損と、存在するが読めない/壊れた JSON を同一視しない。署名履歴が
        # 残る欠損も初回扱いで全 BAN を消さない。
        if observed or _path_presence(path) is not False:
            return None
        if had_hw:
            return MISSING_WITH_HISTORY_FINGERPRINT
        if _path_presence(_hw_path(path)) is not False or floor > 0:
            return None
        return MISSING_FINGERPRINT
    state, payload = _read_signed_json_locked(path, key, _UNREAD, False, raw=raw)
    if state == "unsigned":
        if _path_presence(_hw_path(path)) is not False or floor > 0:
            return None
    elif state == "ok":
        version = _int_or(raw.get("_ver", 0)) if isinstance(raw, dict) else 0
        if version < floor:
            return None
        if version <= 0 and floor > 0:  # 旧 _sv:1 への降格
            return None
    else:
        return None
    try:
        return payload_fingerprint(payload)
    except Exception:
        return None


def _repairable_rollback_locked(path: str, key: bytes) -> bool:
    """Allow an explicit no-CAS writer to repair only a valid bound rollback.

    The existing state may be older than its verified highwater after a
    failed main commit or clock rollback.  The next signed write must still
    be possible.  An invalid main, stale .tmp, or pre-purpose legacy format
    is never accepted as a repair baseline.
    """
    try:
        raw, _observed = _read_signed_candidate(path)
    except OSError:
        return False
    if not isinstance(raw, dict):
        return False
    try:
        if int(raw.get("_sv", 1)) < 3:
            return False
    except (TypeError, ValueError, OverflowError):
        return False
    state, _payload = _read_signed_json_locked(path, key, None, True, raw=raw)
    return state == "rolled_back"


def write_signed_json(path: str, obj, key: bytes, *, indent: int = 2,
                      status: dict | None = None,
                      expected_fingerprint: str | None = None) -> bool:
    """obj を署名エンベロープ(単調バージョン付き=ロールバック耐性)で原子的に書き込む。
    bool は本体の公開成否。status は published/durable を区別する。dir fsync が
    rename 後に失敗しても本体は公開済みなので True + durable=False を返し、
    呼出側は新しいメモリ状態を保ったまま永続化失敗を報告できる。
    _sv:3 で **purpose(ファイル basename)を署名対象に束縛** する(#3): 全状態ファイルが同一鍵で
    署名されるため、旧 _sv:2(purpose 無し)では usage.json の正署名エンベロープを blocklist.json
    へ *移植* すると有効判定され、無警告で BAN 全消し/署名無効化ができた。purpose を署名に含め
    読込時に basename と照合することで、あるファイルの署名を別ファイルとして通せなくする。"""
    if status is not None:
        status.clear()
        status.update(published=False, durable=False, conflict=False, stage="lock")
    with _state_guard(path) as locked:
        if not locked:
            return False
        hw_present = _path_presence(_hw_path(path))
        if hw_present is None or (hw_present and not _read_file_hw_meta(path, key)[2]):
            if status is not None:
                status.update(conflict=True, stage="highwater-invalid")
            return False
        if expected_fingerprint is not None:
            valid = (type(expected_fingerprint) is str
                     and (expected_fingerprint in
                          (MISSING_FINGERPRINT, MISSING_WITH_HISTORY_FINGERPRINT)
                          or (len(expected_fingerprint) == 64
                              and all(ch in "0123456789abcdef"
                                      for ch in expected_fingerprint))))
            current = _cas_fingerprint_locked(path, key) if valid else None
            if current is None or current != expected_fingerprint:
                if status is not None:
                    status.update(conflict=True, stage="conflict")
                return False
        elif (_cas_fingerprint_locked(path, key) is None
              and not _repairable_rollback_locked(path, key)):
            # Even an unconditional writer must not legitimize a corrupt
            # signed main or an older valid .tmp left next to it.  A valid
            # purpose-bound rollback can be repaired against its .hw floor.
            if status is not None:
                status.update(conflict=True, stage="conflict")
            return False
        old_hw, old_min, had_hw = _read_file_hw_meta(path, key)
        hw_present = _path_presence(_hw_path(path))
        if hw_present is None or (hw_present and not had_hw):
            if status is not None:
                status.update(conflict=True, stage="highwater-invalid")
            return False
        ver = _next_version(path, _MEM_HW.get(path, 0), old_hw)
        purpose = os.path.basename(path)
        try:
            env = {"_sv": 3, "_ver": ver, "_purpose": purpose,
                   "_sig": sign_payload({"_ver": ver, "_purpose": purpose,
                                        "_payload": obj}, key), "_payload": obj}
            saved_fingerprint = payload_fingerprint(obj)
        except Exception:
            if status is not None:
                status["stage"] = "sign"
            return False
        # 本体を先に公開すると、後続の .hw 保存失敗で「成功」と答えながら旧署名へ
        # 巻き戻せる。高水位を先に耐久化し、同じロックを取る読み手には途中を見せない。
        hw_status = {}
        if not _write_file_hw(path, ver, key, min_sv=3, status_out=hw_status):
            # post-rename の dir fsync だけが失敗した場合は新 .hw が見えて
            # 旧本体を rolled_back にする。戻せるなら旧高水位へ戻す。
            if hw_status.get("published"):
                if had_hw:
                    _write_file_hw(path, old_hw, key, min_sv=old_min)
                else:
                    try:
                        os.unlink(_hw_path(path))
                    except OSError:
                        pass
            if status is not None:
                status.update(stage="highwater",
                              highwater_published=hw_status.get("published", False),
                              highwater_durable=hw_status.get("durable", False))
            return False
        if status is not None:
            status.update(stage="main", highwater_published=True,
                          highwater_durable=hw_status.get("durable", True))
        main_status = {}
        try:
            saved = atomic_write_json(path, env, indent=indent, status=main_status)
        except Exception:
            saved = False
        if not saved and main_status.get("published") is True:
            # 下層がrename後の追加処理で失敗を返しても、main は既に新値。
            # 旧 .hw へ戻すとディスク新値とメモリ旧値が食い違う。
            saved = True
        if not saved:
            # 本体は旧版のまま。可能なら高水位を戻す。戻せなければ前進した .hw を
            # 残すので、次回読込は rolled_back となり安全側へ倒れる。
            if had_hw:
                _write_file_hw(path, old_hw, key, min_sv=old_min)
            else:
                try:
                    os.unlink(_hw_path(path))
                except OSError:
                    pass
            if status is not None:
                status.update(stage="main",
                              main_published=main_status.get("published", False))
            return False
        _MEM_HW[path] = ver
        _MEM_MIN_SV[path] = 3
        if status is not None:
            hw_durable = hw_status.get("durable", True)
            main_durable = main_status.get("durable", True)
            durable = (False if hw_durable is False or main_durable is False else
                       None if hw_durable is None or main_durable is None else True)
            status.update(published=True, durable=durable, stage="published",
                          main_published=True, fingerprint=saved_fingerprint)
        return True


def read_signed_json(path: str, key: bytes, default=None, *, check_rollback: bool = True,
                     payload_validator=None):
    """署名付き状態を読む。返り値 (status, value)。status は
    ok / tampered / rolled_back / unsigned / missing。例外は投げない。
    rolled_back = 署名は正しいが『過去の版』への巻き戻し(古い正署名ファイルでの上書き)を検知。
    payload_validator は署名確認後・高水位更新前に呼ぶ。旧 purpose 非束縛形式を
    別用途の正署名ファイルで置換されても、その版を受理・記録しない。"""
    try:
        os.lstat(os.path.dirname(path) or ".")
    except FileNotFoundError:
        return ("missing", default)
    except OSError:
        return ("tampered", default)
    try:
        with _state_guard(path) as locked:
            return (_read_signed_json_locked(path, key, default, check_rollback,
                                             payload_validator=payload_validator)
                    if locked else ("tampered", default))
    except Exception:
        return ("tampered", default)


def _read_signed_json_locked(path: str, key: bytes, default, check_rollback: bool,
                             *, raw=_UNREAD, payload_validator=None):
    hw_present = _path_presence(_hw_path(path))
    if hw_present is None or (hw_present and not _read_file_hw_meta(path, key)[2]):
        return ("tampered", default)
    if raw is _UNREAD:
        raw, observed = _read_signed_candidate(path)
    else:
        observed = True
    if raw is None:
        # A present but unreadable/corrupt main file is not a pristine first
        # boot. In particular, a legacy signed BAN file may have no .hw yet.
        # Calling it missing would let that entire BAN set disappear on reload.
        if not observed:
            return ("missing", default)
        return ("tampered", default)
    if isinstance(raw, dict) and "_sig" in raw and "_payload" in raw:
        try:
            _sv = int(raw.get("_sv", 1) or 1)
        except (TypeError, ValueError, OverflowError):
            return ("tampered", default)     # _sv が非数値/Infinity=エンベロープ破損→フェイルセーフ(#111)
        if _sv >= 3:
            # purpose 束縛版(#3): basename が一致し、かつ {_ver,_purpose,_payload} の署名が正しいこと。
            purpose = os.path.basename(path)
            if raw.get("_purpose") != purpose:
                return ("tampered", default)     # 別ファイルからの署名エンベロープ移植=拒否
            ver = raw.get("_ver", 0)
            if not verify_payload({"_ver": ver, "_purpose": purpose,
                                   "_payload": raw["_payload"]}, raw["_sig"], key):
                return ("tampered", default)     # 署名不一致(ver/purpose/payload 改竄)
            if not _payload_valid(raw["_payload"], payload_validator):
                return ("tampered", default)
            v = _int_or(ver)
            if check_rollback:
                file_hw, min_sv, _ = _read_file_hw_meta(path, key)
                hw = max(file_hw, _MEM_HW.get(path, 0))
                if v < hw:
                    return ("rolled_back", default)
                hw = max(hw, v)
                if (file_hw < hw or min_sv < 3) and not _write_file_hw(path, hw, key, min_sv=3):
                    return ("tampered", default)
                _MEM_HW[path], _MEM_MIN_SV[path] = hw, 3
            return ("ok", raw["_payload"])
        if _sv >= 2 and "_ver" in raw:
            ver = raw.get("_ver", 0)
            if not verify_payload({"_ver": ver, "_payload": raw["_payload"]},
                                  raw["_sig"], key):
                return ("tampered", default)     # 署名不一致(ver/payload 改竄)
            if not _payload_valid(raw["_payload"], payload_validator):
                return ("tampered", default)
            v = _int_or(ver)
            file_hw, min_sv, _ = _read_file_hw_meta(path, key)
            if max(min_sv, _MEM_MIN_SV.get(path, 0)) >= 3:
                return ("rolled_back", default)   # v3 保存後の目的束縛なし旧形式は移植可能
            if check_rollback:
                hw = max(file_hw, _MEM_HW.get(path, 0))
                if v < hw:
                    return ("rolled_back", default)   # 旧い正署名への巻き戻し=拒否
                hw = max(hw, v)
                if (file_hw < hw or min_sv < 2) and not _write_file_hw(path, hw, key, min_sv=2):
                    return ("tampered", default)
                _MEM_HW[path], _MEM_MIN_SV[path] = hw, 2
            return ("ok", raw["_payload"])
        # 旧 _sv:1(バージョン無し)= 後方互換: payload 署名のみ検証
        if verify_payload(raw["_payload"], raw["_sig"], key):
            if not _payload_valid(raw["_payload"], payload_validator):
                return ("tampered", default)
            file_hw, min_sv, _ = _read_file_hw_meta(path, key)
            if max(min_sv, _MEM_MIN_SV.get(path, 0)) >= 3:
                return ("rolled_back", default)
            if check_rollback:
                hw = max(file_hw, _MEM_HW.get(path, 0))
                if hw > 0:
                    # このpathは既に _sv:2(バージョン付き)で保存された実績がある。
                    # 旧形式への「降格」は #102 のロールバック対策を素通りする巻き戻し攻撃と
                    # みなして拒否する(初回移行時=hw==0 の間は従来どおり受理・#111)。
                    return ("rolled_back", default)
            return ("ok", raw["_payload"])
        return ("tampered", default)            # 署名不一致=改竄/すり替え→フェイルセーフ
    return ("unsigned", raw)                     # 旧来の無署名(移行対象)


def _payload_valid(payload, validator) -> bool:
    if validator is None:
        return True
    try:
        return validator(payload) is True
    except Exception:
        return False
