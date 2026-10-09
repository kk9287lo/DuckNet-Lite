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

import json
import os
import tempfile
import threading
import time
from typing import Any

_MAX_READ_BYTES = 64 * 1024 * 1024   # 状態JSONの読込上限(#111: 書込権限を持つ攻撃者が巨大
                                      # ファイルを置いてメモリ/CPUを浪費させる DoS を防ぐ)

# Windows の共有違反: Python の open() は FILE_SHARE_DELETE 無しで開くため、誰か(管理 API の
# 読み手・別プロセス・ウイルス対策/インデクサ)が開いている間は os.replace が、置換の最中は
# open が PermissionError になる。POSIX には無い一時的な失敗なので、Windows でだけ短い有界
# バックオフで再試行する(合計 約 0.43 秒で諦める)。POSIX の PermissionError は本物の権限
# 不足なので待たない。
# ただし要求経路では眠らない: ログのローテーションは再試行せず(握られていれば見送って
# _ROTATE_RETRY_SEC 後に 1 回だけ試し直す)、append_jsonl(wait=False) は開けなければ待たずに諦める。
# 読み手が tail している間、要求ごとに約 0.43 秒眠って要求処理が止まっていた。
_WIN = os.name == "nt"
_SHARE_RETRIES = 10
_ROTATE_RETRY_SEC = 5.0              # 回せなかったログは、この間ローテーションを試さない
_ROTATE_BLOCKED: dict = {}           # abspath -> 最後に回せなかった時刻(monotonic)


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


def default_state_dir() -> str:
    """状態ファイルの既定の置き場。環境変数 DUCKNET_STATE_DIR で上書きできる
    (ステルス運用で『どこに何を書くか』を秘匿/移設するための一点)。既定は ~/.cache/dataplane
    (ありふれたアプリのキャッシュ置き場に偽装=ブランド名を露出しない)。"""
    return (os.environ.get("DUCKNET_STATE_DIR")
            or os.path.join(os.path.expanduser("~"), ".cache", "dataplane"))


def atomic_write_text(path: str, text: str, *, encoding: str = "utf-8",
                      errors: str = "strict") -> bool:
    """text を path へ原子的に書き込む。成功で True。失敗してもオリジナルは無傷。
    一時ファイル名はランダム化し O_CREAT|O_EXCL で新規作成する(#111: 旧来の predictable な
    `path.tmp.<pid>` は、状態dirが(ステルス運用等で)共有/書込可能な場所を指す構成だと、
    攻撃者が先回りしてシンボリックリンクを置き『任意ファイル上書き』へ転用できた)。"""
    tmp = None
    try:
        d = os.path.dirname(path) or "."
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=d)
        with os.fdopen(fd, "w", encoding=encoding, errors=errors) as f:
            f.write(text)
            f.flush()
            try:
                os.fsync(f.fileno())          # ディスクへ確実に
            except OSError:
                pass
        _retry_sharing(os.replace, tmp, path)  # 原子置換(同一FS)。Windows の共有違反は待って再試行
        tmp = None
        try:                                  # 親ディレクトリも同期(対応FSのみ)
            dfd = os.open(d, os.O_RDONLY)
            try:
                os.fsync(dfd)
            except OSError:
                pass
            finally:
                os.close(dfd)
        except (OSError, AttributeError):
            pass
        return True
    except Exception:
        return False
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except Exception:
                pass


def atomic_write_json(path: str, obj: Any, *, indent: int = 2) -> bool:
    """obj を JSON で path へ原子的に書き込む。"""
    try:
        text = json.dumps(obj, ensure_ascii=False, indent=indent)
    except Exception:
        return False
    # backslashreplace: json.loads は '\udc80' のような孤立サロゲートをそのまま作るが、厳格な
    # UTF-8 では書けず保存が黙って失敗していた(管理 API で入った値 1 つで以後の保存が全滅)。
    # JSON 出力で UTF-8 に書けないのは文字列中の孤立サロゲートだけで、その \udXXX 表記は
    # JSON の正しいエスケープ=読み戻すと同じ値になる。それ以外の文字は従来どおり生で書く。
    return atomic_write_text(path, text, errors="backslashreplace")


def safe_read_json(path: str, default: Any = None) -> Any:
    """JSON を読む。壊れ/欠損/権限エラーでも例外を投げず default を返す。
    本体が壊れていて path.tmp が残っていれば、そこからの回復を試みる。
    書込権限を持つ攻撃者が巨大ファイルを置いて読込側のメモリ/CPUを浪費させる DoS を
    防ぐため、_MAX_READ_BYTES を超えるファイルは壊れているものとして扱う(#111)。"""
    for candidate in (path, path + ".tmp"):
        try:
            if os.path.isfile(candidate):
                if os.path.getsize(candidate) > _MAX_READ_BYTES:
                    continue
                # 置換の最中/他ハンドル保持中の一時的な共有違反(Windows)を『欠損』扱いしない
                # (署名付き状態が 'missing' に見えて既定値へ戻っていた)。
                return _retry_sharing(_load_json_file, candidate)
        except Exception:
            continue
    return default


def _load_json_file(p: str):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)   # POSIX: 最終要素が symlink なら失敗


def _rotate(path: str, backups: int) -> bool:
    """path → path.1 → … → path.{backups} と押し出し、最古は破棄。眠らない(要求経路から呼ばれる)。
    先に現行を一時名へ退避する: 読み手が握っていればここで失敗し、世代には一切触らない(旧実装は
    最古の削除と押し出しを済ませてから現行の改名に失敗し、失敗のたびに世代を 1 つずつ削っていた)。
    path.1 を空けられなければ現行へ戻す。戻り値: 回せたか(False=今回は見送り・行は失わない)。"""
    staged = f"{path}.rot-{os.urandom(4).hex()}"
    try:
        os.replace(path, staged)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    oldest = f"{path}.{backups}"
    try:
        if os.path.exists(oldest):
            os.unlink(oldest)
    except Exception:
        pass
    for i in range(backups, 1, -1):           # path.(i-1) → path.i
        try:
            src = f"{path}.{i - 1}"
            if os.path.exists(src):
                os.replace(src, f"{path}.{i}")
        except Exception:
            pass
    first = f"{path}.1"
    if not os.path.exists(first):             # 押し出せなかった path.1 を上書きしない
        try:
            os.replace(staged, first)             # 現行 → path.1
            return True
        except OSError:
            pass
    try:
        os.replace(staged, path)
    except OSError:
        pass
    return False


def append_jsonl(path: str, obj: Any, *, max_bytes: int = 5_000_000,
                 backups: int = 1, encoding: str = "utf-8", wait: bool = True) -> bool:
    """1行 JSON を追記する。追記後にサイズ上限を超えそうなら先にローテーションする。
    追記ログ(監査ログ)の無制限肥大を防ぐ共有ヘルパ。失敗しても例外は投げない。
    ローテーションは眠らない: 読み手が握っていれば見送り(上限を超えて追記を続ける)、
    _ROTATE_RETRY_SEC 後の追記で 1 回だけ試し直す。
    wait=False は要求経路(イベントループ・接続処理)用: Windows の共有違反で開けなくても待たずに
    諦める(False)。既定の wait=True は管理操作の監査など、短く待ってでも行を残したい書き手用。"""
    try:
        line = json.dumps(obj, ensure_ascii=False) + "\n"
    except Exception:
        return False
    try:
        d = os.path.dirname(path) or "."
        os.makedirs(d, exist_ok=True)
        # 同一プロセスの複数スレッド(ThreadingHTTPServer の管理 API 等)がローテーションを
        # 同時に走らせると、押し出し(.1→.2 …)が交錯して世代ファイルを上書きし行が消えていた。
        # サイズ判定〜ローテーション〜追記をパス単位で直列化する。
        with _append_lock(path):
            try:
                cur = os.path.getsize(path)
            except OSError:
                cur = 0
            if cur and cur + len(line.encode(encoding, "replace")) > max_bytes:
                key = os.path.abspath(path)
                now = time.monotonic()
                last = _ROTATE_BLOCKED.get(key)
                if last is None or now - last >= _ROTATE_RETRY_SEC:
                    if _rotate(path, max(1, backups)):
                        _ROTATE_BLOCKED.pop(key, None)
                    else:
                        _ROTATE_BLOCKED[key] = now
            opened = (_retry_sharing(_open_append_nofollow, path, encoding) if wait
                      else _open_append_nofollow(path, encoding))
            with opened as f:
                f.write(line)
        return True
    except Exception:
        return False


_APPEND_LOCKS: dict = {}
_APPEND_LOCKS_GUARD = threading.Lock()


def _append_lock(path: str):
    key = os.path.abspath(path)
    with _APPEND_LOCKS_GUARD:
        lk = _APPEND_LOCKS.get(key)
        if lk is None:
            lk = _APPEND_LOCKS[key] = threading.Lock()
        return lk


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
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | _O_NOFOLLOW, 0o600)
    # backslashreplace: 孤立サロゲートを含む行を UnicodeEncodeError で黙って捨てない
    # (JSON 文字列中の \udXXX はそのまま正しいエスケープ。atomic_write_json と同じ理由)。
    return os.fdopen(fd, "a", encoding=encoding, errors="backslashreplace")


_TAIL_AVG_LINE = 512   # 末尾読みの初期見積り(1行あたりバイト数)
_TAIL_MAX_ROUNDS = 6   # 見積りが外れた時の読み直し上限(有界化)


def tail_jsonl(path: str, n: int = 50) -> list:
    """JSONL ファイル末尾の最大 n 行を新しい順(末尾=最新が先頭)で読む。
    欠損/壊れ行は飛ばし、例外は投げない(管理画面の横断表示などに使う)。"""
    try:
        if not os.path.isfile(path):
            return []
        n = max(1, n)
        # 末尾 n 行が欲しいだけなのに readlines() でファイル全体を読み込んでいた。
        # 管理画面がポーリングで叩くため、ログが育つほど 1 回の読み取り量が増える
        # (= 蓄積量 x ポーリング回数)。末尾から必要なぶんだけ遡って読む。
        want = n * _TAIL_AVG_LINE
        with _retry_sharing(open, path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            for _ in range(_TAIL_MAX_ROUNDS):
                start = max(0, size - want)
                f.seek(start)
                raw = f.read(size - start)
                # 行区切りは *バイトの* \n だけ。str.splitlines() は U+0085/U+2028/U+2029 でも
                # 割るため、それを含む記録(latin-1 で読んだ UA の 0x85 等)が 2 つの壊れた断片に
                # なって捨てられ、管理画面から消えていた(ログ回避)。UTF-8 の多バイト文字は
                # 0x0A を含まないので、復号前に割っても文字は壊れない。
                lines = [ln.decode("utf-8", "replace") for ln in raw.split(b"\n")]
                if lines and not lines[-1].strip():
                    lines.pop()                 # 末尾の改行が作る空要素(splitlines と同じ数え方)
                if start > 0:
                    lines = lines[1:]           # 先頭は途中で切れている可能性がある
                if len(lines) >= n or start == 0:
                    break
                want *= 4                       # 行が長かった=範囲を広げて読み直す
        lines = lines[-n:]
    except Exception:
        return []
    out = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def safe_read_text(path: str, default: str = "") -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return default
