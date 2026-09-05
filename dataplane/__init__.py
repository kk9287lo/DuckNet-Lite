"""
DuckNet-Lite — 軽量 DDoS / WAF セキュリティゲートウェイ(無償 AGPL エディション)
==========================================================================
DuckNet の防御コア(app_firewall / pipeline / proxy)を、単独で
配布・サービス化できる製品として束ねたパッケージ。外部依存ゼロ・L7・OS非侵襲・防御専用。

  · gateway … 前衛ガード(asyncio Fail-Fast) + 管理ダッシュボードを起動する製品本体。
  · admin   … Web 管理ダッシュボード(stdlib・ON/OFF/指標/BAN/設定)。
"""
from .service import run, main          # noqa: F401
from .admin import AdminDashboard       # noqa: F401

__version__ = "1.0.0"
# 販売(製品)名。内部パッケージ名(dataplane)は据え置き=表示/販売用ブランドのみ。
# 実行時に名乗る名前。上位(商用)エディションの "DuckNet L7 Security" とは区別する:
# 管理画面・遮断ページ・CLI・OS の自動起動エントリはすべてこの名前で表示される。
BRAND = "DuckNet-Lite"
__product__ = BRAND
