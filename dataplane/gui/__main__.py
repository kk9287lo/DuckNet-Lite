"""
__main__.py — DuckNet-Lite: システムトレイ常駐(トレイのみ・依存ゼロ)
====================================================================================
`python -m dataplane tray` / `python -m dataplane.gui` で起動。タスクトレイに DuckNet.ico を
常駐させ、右クリックメニューから最小操作を提供する:
  · ダッシュボードを開く … 既定ブラウザで管理ダッシュボード(DUCKNET_ADMIN_URL)を開く
  · About              … 製品/版の情報(Win32 MessageBox)
  · 無料版でできること   … このエディションで使える機能一覧(上位版との差は README/❓ヘルプ参照)
  · 終了               … 本launcher が起動した本体を停止し、トレイを外してプロセス終了
起動時、本体(ゲートウェイ)が未起動なら子プロセスとして一緒に立ち上げる(既に稼働中なら起動しない)。
backend/listen は env DUCKNET_BACKEND / DUCKNET_LISTEN で上書き可(既定 127.0.0.1:8080 / 8443)。
上位版のようなコントロールパネルは持たない(Lite=最小構成)。Windows 専用(他 OS はトレイ非対応の旨を表示)。
"""
from __future__ import annotations

import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import webbrowser
import urllib.error
import urllib.request
from urllib.parse import urlparse

from . import tray, ASSET_ICO

_ADMIN_URL = os.environ.get("DUCKNET_ADMIN_URL", "http://127.0.0.1:8081")
_BRAND = os.environ.get("DUCKNET_COVER", "").strip() or "DuckNet-Lite"

_ABOUT_TEXT = (
    "{brand}\n\n"
    "軽量 L7 WAF / DDoS セキュリティゲートウェイ(無償エディション・AGPL)。\n"
    "外部依存ゼロ(Python 標準ライブラリのみ)・OS 非侵襲・防御専用。\n\n"
    "コアの L7 WAF/DDoS リバースプロキシと Web 管理ダッシュボードを提供します。\n"
    "詳細は README.md / docs、ダッシュボード右上の ❓ ヘルプを参照してください。"
).format(brand=_BRAND)

_CAPS_TEXT = (
    "無料版(DuckNet-Lite)でできること:\n\n"
    "・WAF: SQLi / XSS / RCE / パストラバーサル / XXE / SSRF / JNDI / スキャナー等の\n"
    "  シグネチャ照合、カスタムシグネチャ追加\n"
    "・L7 DDoS 防御: レート制限・脅威スコアリング・自動BAN(拒否/BAN の2段階)\n"
    "・双方向検査: リクエストボディ(POST/JSON/GraphQL・gzip/chunked 復号)+ 応答の\n"
    "  DLP・セキュリティヘッダ付与\n"
    "・認証/濫用対策: JWT 検査・クレデンシャル単位のレート制限\n"
    "・状態の整合性: BAN/設定の HMAC 署名による改竄耐性\n\n"
    "PoW チャレンジ・DNS フィルタ・SIEM 転送・自己完全性監視・watchdog・GeoIP・\n"
    "横展開デコイ・脅威インテリジェンス・分散BAN同期・ハニーポット等は上位版(DuckNet)で。"
)


def _asset_path(name: str) -> str:
    """アイコンの場所を解決: env DUCKNET_ICON_DIR → リポジトリ/カレントの ico/ → 同梱 assets/。"""
    here = os.path.dirname(__file__)
    repo_root = os.path.dirname(os.path.dirname(here))     # …/dataplane/gui → リポジトリ直下
    cands = []
    env = os.environ.get("DUCKNET_ICON_DIR", "").strip()
    if env:
        cands.append(os.path.join(env, name))
    for root in (repo_root, os.getcwd()):
        cands.append(os.path.join(root, "ico", name))
    bundled = os.path.join(here, "assets", name)
    cands.append(bundled)
    for p in cands:
        try:
            if p and os.path.exists(p):
                return p
        except Exception:
            pass
    return bundled


def _msgbox(text: str, title: str) -> None:
    """Win32 MessageBox(情報アイコン)。tkinter 非依存。失敗は無害。"""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, text, title, 0x40)   # MB_ICONINFORMATION
    except Exception:
        pass


# ── 本体(ゲートウェイ)の自動起動 ──────────────────────────────────────
def _admin_addr(base_url: str):
    """管理APIの (host, port) を DUCKNET_ADMIN_URL から解く。"""
    u = urlparse(base_url if "://" in base_url else "http://" + base_url)
    return (u.hostname or "127.0.0.1", int(u.port or 8081))


def _gateway_up(host: str, port: int, timeout: float = 0.5) -> bool:
    """本体(前衛+管理API)が既にそのポートで待受けているか。"""
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


def _spawn_gateway(admin_port: int, token: str):
    """本体(ゲートウェイ)を子プロセスで起動する。コンソール窓は出さない。ローカル(127.0.0.1)
    からブラウザで開けば自動でトークン Cookie が発行される。失敗時は None。"""
    backend = os.environ.get("DUCKNET_BACKEND", "127.0.0.1:8080")
    listen = os.environ.get("DUCKNET_LISTEN", "8443")
    cmd = [sys.executable, "-m", "dataplane",
           "--backend", backend, "--listen", str(listen),
           "--admin", str(admin_port), "--admin-host", "127.0.0.1"]
    # トークンは argv ではなく env で渡す: コマンドラインは他ユーザーから読める
    # (Linux の /proc/<pid>/cmdline は world-readable、Windows は WMI で取得可)。
    # env(/proc/<pid>/environ)は同一UID/root 限定=露出面が小さい。
    child_env = dict(os.environ)
    child_env["DUCKNET_ADMIN_TOKEN"] = token
    kw = {"stdin": subprocess.DEVNULL, "env": child_env,
          "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if sys.platform.startswith("win"):
        kw["creationflags"] = 0x08000000 | 0x00000200   # CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    try:
        return subprocess.Popen(cmd, **kw)
    except Exception:
        return None


def _admin_is_ours(host: str, port: int, timeout: float = 1.0) -> bool:
    """待受けているのが本製品の管理APIかを *トークンを送らずに* 確かめる。無認証の
    GET /api/state は 401 + {"ok": false, "error": "token required"} を返すので、これを指紋にする。
    別プロセスのポート占有を『本体が稼働中』と誤認し、起動を諦めたり秘密を渡したりしないため。"""
    url = "http://%s:%d/api/state" % (host, port)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as _r:
            _r.read(1)
        return False                              # 200=無認証で応答する別物(本製品は 401)
    except urllib.error.HTTPError as e:
        if e.code != 401:
            return False
        try:
            body = e.read(256)
        except Exception:
            return False
    except Exception:
        return False
    return b"token required" in body


def _ensure_gateway(base_url: str, token: str):
    """本体が起動していなければ起動する。戻り値 (token, child)。child は本launcher が起動した
    子プロセス(既に稼働中なら None=触らない)。起動時は管理APIが上がるまで最大 ~6 秒待つ。"""
    host, port = _admin_addr(base_url)
    if _gateway_up(host, port):
        if not _admin_is_ours(host, port):        # 別プロセスのポート占有を稼働中と誤認しない
            print("[警告] %s:%d は本製品以外のプロセスが使用しています。ゲートウェイを起動できず、"
                  "保護は動作していません。" % (host, port), file=sys.stderr)
            return "", None                       # 占有プロセスへトークンを渡さない
        return token, None
    tok = token or secrets.token_urlsafe(24)
    child = _spawn_gateway(port, tok)
    if child is not None:
        for _ in range(30):
            if _gateway_up(host, port):
                break
            time.sleep(0.2)
    return tok, child


def _stop_child(child):
    """本launcher が起動した子プロセス(本体)を穏当に停止する。None/停止済みは無視。"""
    if child is None:
        return
    try:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except Exception:
                child.kill()
    except Exception:
        pass


def main(argv=None) -> int:
    if not tray.available():
        print("トレイ常駐は Windows 専用です(他 OS では非対応)。"
              "Lite は CLI + Web ダッシュボードで運用してください。", file=sys.stderr)
        return 0

    # 本体(ゲートウェイ)も一緒に起動: 管理APIが未待受なら子プロセスで起動する
    # (既に稼働中なら起動しない)。gw は終了時に停止する。
    _tok, gw = _ensure_gateway(_ADMIN_URL, os.environ.get("DUCKNET_ADMIN_TOKEN", ""))

    stop = threading.Event()

    items = [("ダッシュボードを開く", "dash"), None,
             ("About", "about"),
             ("無料版でできること", "caps"), None,
             ("終了", "quit")]

    ti = None

    def _on_action(aid):
        if aid == "dash":
            try:
                webbrowser.open(_ADMIN_URL)
            except Exception:
                pass
        elif aid == "about":
            _msgbox(_ABOUT_TEXT, "About — " + _BRAND)
        elif aid == "caps":
            _msgbox(_CAPS_TEXT, _BRAND)
        elif aid == "quit":
            try:
                if ti is not None:
                    ti.stop()
            finally:
                stop.set()

    ti = tray.TrayIcon(_asset_path(ASSET_ICO), _BRAND, items, _on_action)
    if not ti.start():
        print("トレイの起動に失敗しました。", file=sys.stderr)
        _stop_child(gw)
        return 1
    try:
        stop.wait()                      # 終了が選ばれるまでメインスレッドを生かす
    except KeyboardInterrupt:
        ti.stop()
    finally:
        _stop_child(gw)                  # 本launcher が起動した本体を停止(既存稼働は触らない)
    return 0


if __name__ == "__main__":
    sys.exit(main())
