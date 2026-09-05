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
from typing import Any

_MAX_READ_BYTES = 64 * 1024 * 1024   # 状態JSONの読込上限(#111: 書込権限を持つ攻撃者が巨大
                                      # ファイルを置いてメモリ/CPUを浪費させる DoS を防ぐ)


def default_state_dir() -> str:
    """状態ファイルの既定の置き場。環境変数 DUCKNET_STATE_DIR で上書きできる
    (ステルス運用で『どこに何を書くか』を秘匿/移設するための一点)。既定は ~/.cache/dataplane
    (ありふれたアプリのキャッシュ置き場に偽装=ブランド名を露出しない)。"""
    return (os.environ.get("DUCKNET_STATE_DIR")
            or os.path.join(os.path.expanduser("~"), ".cache", "dataplane"))


def atomic_write_text(path: str, text: str, *, encoding: str = "utf-8") -> bool:
    """text を path へ原子的に書き込む。成功で True。失敗してもオリジナルは無傷。
    一時ファイル名はランダム化し O_CREAT|O_EXCL で新規作成する(#111: 旧来の predictable な
    `path.tmp.<pid>` は、状態dirが(ステルス運用等で)共有/書込可能な場所を指す構成だと、
    攻撃者が先回りしてシンボリックリンクを置き『任意ファイル上書き』へ転用できた)。"""
    tmp = None
    try:
        d = os.path.dirname(path) or "."
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=d)
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(text)
            f.flush()
            try:
                os.fsync(f.fileno())          # ディスクへ確実に
            except OSError:
                pass
        os.replace(tmp, path)                 # 原子置換(同一FS)
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
    return atomic_write_text(path, text)


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
                with open(candidate, encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            continue
    return default


_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)   # POSIX: 最終要素が symlink なら失敗


def _rotate(path: str, backups: int) -> None:
    """path → path.1 → … → path.{backups} と押し出し、最古は破棄。失敗は無害に握る。"""
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
    try:
        if os.path.exists(path):
            os.replace(path, f"{path}.1")     # 現行 → path.1
    except Exception:
        pass


def append_jsonl(path: str, obj: Any, *, max_bytes: int = 5_000_000,
                 backups: int = 1, encoding: str = "utf-8") -> bool:
    """1行 JSON を追記する。追記後にサイズ上限を超えそうなら先にローテーションする。
    追記ログ(監査ログ)の無制限肥大を防ぐ共有ヘルパ。失敗しても例外は投げない。"""
    try:
        line = json.dumps(obj, ensure_ascii=False) + "\n"
    except Exception:
        return False
    try:
        d = os.path.dirname(path) or "."
        os.makedirs(d, exist_ok=True)
        try:
            cur = os.path.getsize(path)
        except OSError:
            cur = 0
        if cur and cur + len(line.encode(encoding, "replace")) > max_bytes:
            _rotate(path, max(1, backups))
        with _open_append_nofollow(path, encoding) as f:
            f.write(line)
        return True
    except Exception:
        return False


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
    return os.fdopen(fd, "a", encoding=encoding)


def tail_jsonl(path: str, n: int = 50) -> list:
    """JSONL ファイル末尾の最大 n 行を新しい順(末尾=最新が先頭)で読む。
    欠損/壊れ行は飛ばし、例外は投げない(管理画面の横断表示などに使う)。"""
    try:
        if not os.path.isfile(path):
            return []
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-max(1, n):]
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
