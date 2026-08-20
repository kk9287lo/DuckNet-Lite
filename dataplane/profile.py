"""
profile.py — フィンガープリント低減(ステルス運用・防御専用・OS非侵襲・依存ゼロ)
====================================================================================
侵入後の攻撃者が本機を『ChickenNet という防御ツール』と特定し、狙って無効化するのを
難しくする。プロセス名/コンソール(ウィンドウ)タイトルを汎用名へ偽装し、表示ブランドを
伏せ、状態ファイルの場所を移せるようにする(=こちらの手の内を見せない)。

正直な限界(誇張しない):
  · これは『紛れ込ませる(blend-in)/指紋を薄める』であって rootkit ではない。
    OSのプロセス列挙をフックして隠したり、他プロセス/カーネルへ干渉することは一切しない
    (OS非侵襲を死守)。本機 *自身* のプロセス名・タイトル・ブランド・ファイル位置だけを
    目立たなくする、userland かつ self-only の措置。
  · 真剣なフォレンジック(メモリ解析・厳密なバイナリ精査・ネットワーク監視)には抗えない。
    『ざっと見・自動列挙・タイトル/プロセス名での当たり』を外す層、と理解すること。

stdlib のみ(ctypes は標準)。失敗しても無害に no-op(防御性能は1ミリも落とさない)。
"""
from __future__ import annotations

import ctypes
import os
import sys

# 既定の偽装名(ありふれた保守系ユーティリティに見せる)。--stealth-name で変更可。
DEFAULT_COVER = "System Health Monitor"


def set_process_title(name: str) -> list:
    """自プロセスの表示名/コンソールタイトルを name へ。適用できた手段名のリストを返す。
    すべて best-effort・例外は握りつぶす(環境差で一部が効かなくても続行)。"""
    applied = []
    safe = (name or DEFAULT_COVER).strip() or DEFAULT_COVER
    # Linux/Unix: prctl(PR_SET_NAME=15) で comm(ps/top/htop の表示名)を変更(15バイト上限)
    if sys.platform.startswith(("linux", "freebsd")):
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            buf = ctypes.create_string_buffer(safe.encode("utf-8", "replace")[:15])
            if libc.prctl(15, ctypes.byref(buf), 0, 0, 0) == 0:
                applied.append("prctl(comm)")
        except Exception:
            pass
    # Windows: コンソールウィンドウのタイトルを変更
    if os.name == "nt":
        try:
            if ctypes.windll.kernel32.SetConsoleTitleW(ctypes.c_wchar_p(safe)):
                applied.append("SetConsoleTitle")
        except Exception:
            pass
    # 端末(xterm系)のウィンドウ/タブタイトル(OSC 0)。非Windowsのtty時のみ。
    if os.name != "nt":
        try:
            out = sys.stdout
            if out is not None and hasattr(out, "isatty") and out.isatty():
                out.write(f"\033]0;{safe}\007")
                out.flush()
                applied.append("xterm-title")
        except Exception:
            pass
    return applied


def cover_thread_name(suffix: str) -> str:
    """常駐スレッド名を cover に従わせる(evolution #81)。`ps -L`/`/proc/*/task/*/comm`/デバッガに
    出るスレッド名から製品名(chickennet)を露出させない。CHICKENNET_COVER 設定時はその先頭語(英数のみ・
    短縮)を、未設定時(=非ステルス)は 'chickennet' を接頭に使う。OS の comm は 15 文字程度で切られる
    ため短く保つ。"""
    import re
    cov = os.environ.get("CHICKENNET_COVER", "").strip()
    base = re.sub(r"[^A-Za-z0-9]", "", cov.split()[0]) if cov else "chickennet"
    return f"{(base[:12] or 'svc').lower()}-{suffix}"


def cover_brand(default: str) -> str:
    """コンソール出力等のブランド表記。ステルス時は cover 名、未設定時は default(製品名可)。"""
    return os.environ.get("CHICKENNET_COVER", "").strip() or default


def apply(name: str = "") -> dict:
    """ステルスを適用。プロセス名/タイトルを偽装し、適用結果を返す(ログ用)。"""
    cover = (name or DEFAULT_COVER)
    return {"cover": cover, "applied": set_process_title(cover)}
