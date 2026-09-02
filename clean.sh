#!/usr/bin/env bash
# =============================================================================
#  clean.sh - DuckNet-Lite: GitHub アップロード前のクリーンアップ(Linux/macOS)
#  生成物/キャッシュ *のみ* を削除する。ソース・ico/画像・app.env・.git は残す。
#  対象は .gitignore と同じ(= Git に上がらない一時物)。
# =============================================================================
set -eu
cd "$(dirname "$0")"
echo "[DuckNet-Lite] cleanup in $(pwd)"

# Python バイトコードキャッシュ
find . -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
find . -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '*.pyd' \) -delete 2>/dev/null || true

# テスト/型/lint/カバレッジ/ビルド生成物
find . -type d \( -name '.pytest_cache' -o -name '.mypy_cache' -o -name '.ruff_cache' \
     -o -name 'htmlcov' -o -name '*.egg-info' \) -prune -exec rm -rf {} + 2>/dev/null || true
rm -rf build dist 2>/dev/null || true
rm -f .coverage 2>/dev/null || true

# ログ(.gitignore で *.log は追跡外)
find . -type f -name '*.log' -delete 2>/dev/null || true

# OS/エディタのゴミ
find . -type f \( -name '.DS_Store' -o -name 'Thumbs.db' -o -name '*.swp' -o -name '*~' \) \
     -delete 2>/dev/null || true

# 注意: app.env / .claude/launch.json は運用者のローカル設定なので *消さない*
#       (.gitignore 済みなのでそもそも Git には上がらない)。ico/ と assets も残す。

echo "[DuckNet-Lite] done. 残ったのはリポジトリに必要なファイルだけです。"
