"""
gui — DuckNet-Lite の最小デスクトップ常駐(システムトレイのみ)
====================================================================================
Lite は上位版のようなコントロールパネル GUI を持たない(意図的に削減)。ここにあるのは
**システムトレイ常駐アイコンだけ**: DuckNet.ico をタスクトレイに出し、右クリックで
「ダッシュボードを開く / About / 無料版でできること / 終了」を提供する軽量プレゼンス。
防御の状態(ON / OFF / 本体に接続できない)はアイコンとツールチップで示す(切替はダッシュボードで)。
依存ゼロ(Windows は ctypes+Win32、ダイアログも MessageBoxW)。tkinter も不要。
起動: `python -m dataplane tray`(または `python -m dataplane.gui`)。Windows 専用。
"""
ASSET_ICO = "DuckNet.ico"
ASSET_ICO_OFF = "DuckNet-off.ico"   # 防御 OFF / 接続不可の淡色版(tools/make_tray_icons.py で生成)
ASSET_PNG = "DuckNet.png"
