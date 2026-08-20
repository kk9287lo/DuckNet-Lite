"""
ChickenNet L7 Security — 軽量 DDoS / WAF セキュリティゲートウェイ(製品パッケージ)
==========================================================================
ChickenNet の防御コア(app_firewall / pipeline / proxy)を、単独で
配布・サービス化できる製品として束ねたパッケージ。外部依存ゼロ・L7・OS非侵襲・防御専用。

  · gateway … 前衛ガード(asyncio Fail-Fast) + 管理ダッシュボードを起動する製品本体。
  · admin   … Web 管理ダッシュボード(stdlib・ON/OFF/指標/BAN/設定)。
"""
from .service import run, main          # noqa: F401
from .admin import AdminDashboard       # noqa: F401

__version__ = "1.0.0"
# 販売(製品)名。内部パッケージ名(dataplane)は据え置き=表示/販売用ブランドのみ。
BRAND = "ChickenNet L7 Security"
__product__ = BRAND
