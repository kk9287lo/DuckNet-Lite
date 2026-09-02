"""
__main__.py — DuckNet-Lite: システムトレイ常駐(トレイのみ・依存ゼロ)
====================================================================================
`python -m dataplane tray` / `python -m dataplane.gui` で起動。タスクトレイに DuckNet.ico を
常駐させ、右クリックメニューから最小操作を提供する:
  · ダッシュボードを開く … 既定ブラウザで管理ダッシュボード(DUCKNET_ADMIN_URL)を開く
  · About              … 製品/版の情報(Win32 MessageBox)
  · 無料版でできること   … このエディションで使える機能一覧(上位版との差は README/❓ヘルプ参照)
  · 終了               … トレイを外してプロセス終了
上位版のようなコントロールパネルは持たない(Lite=最小構成)。Windows 専用(他 OS はトレイ非対応の旨を表示)。
"""
from __future__ import annotations

import os
import sys
import threading
import webbrowser

from . import tray, ASSET_ICO

_ADMIN_URL = os.environ.get("DUCKNET_ADMIN_URL", "http://127.0.0.1:8081")
_BRAND = os.environ.get("DUCKNET_COVER", "").strip() or "DuckNet-Lite"

_ABOUT_TEXT = (
    "{brand}\n\n"
    "軽量 L7 WAF / DDoS セキュリティゲートウェイ(無償/試用エディション)。\n"
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


def main(argv=None) -> int:
    if not tray.available():
        print("トレイ常駐は Windows 専用です(他 OS では非対応)。"
              "Lite は CLI + Web ダッシュボードで運用してください。", file=sys.stderr)
        return 0

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
        return 1
    try:
        stop.wait()                      # 終了が選ばれるまでメインスレッドを生かす
    except KeyboardInterrupt:
        ti.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
