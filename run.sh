#!/usr/bin/env bash
# =============================================================================
# ChickenNet L7 Security — 起動ランチャ (POSIX / Linux・macOS)
# -----------------------------------------------------------------------------
# 役割: Python を堅牢に検出し、バージョンを確認し、UTF-8 を整えて製品本体へ委譲する。
#   ./run.sh                      … ゲートウェイ(前衛 + 管理ダッシュボード)
#   ./run.sh --help               … 製品の全オプション
#
# 環境変数 / 設定:
#   CHICKENNET_PYTHON    使う Python を明示(未設定なら .venv → python3 → python)
#   CHICKENNET_ENV_FILE  読み込む設定ファイル(既定: スクリプトと同じ場所の app.env)
# 終了コード: 製品の終了コードをそのまま返す。起動前提を満たさない場合は 9。
# =============================================================================
set -euo pipefail

readonly MIN="3.10"
SELF="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" >/dev/null 2>&1 && pwd)"
cd "$SELF"

die() { printf 'ChickenNet: %s\n' "$*" >&2; exit 9; }

# 1) 任意の設定ファイル(KEY=VALUE・# はコメント)。source せず安全に取り込む。
ENV_FILE="${CHICKENNET_ENV_FILE:-$SELF/app.env}"
if [ -f "$ENV_FILE" ]; then
  while IFS='=' read -r key val || [ -n "$key" ]; do
    case "$key" in ''|\#*) continue ;; esac
    export "$key=$val"
  done < "$ENV_FILE"
fi

# 2) Python を選ぶ: 明示 → ローカル venv → python3 → python
pick_python() {
  if [ -n "${CHICKENNET_PYTHON:-}" ]; then printf '%s' "$CHICKENNET_PYTHON"; return 0; fi
  local c
  for c in "$SELF/.venv/bin/python" "$SELF/venv/bin/python" python3 python; do
    if command -v "$c" >/dev/null 2>&1; then printf '%s' "$c"; return 0; fi
  done
  return 1
}
PY="$(pick_python)" || die "Python が見つかりません。Python ${MIN}+ を導入するか CHICKENNET_PYTHON を設定してください。"
command -v "$PY" >/dev/null 2>&1 || die "指定の Python が見つかりません/実行できません: $PY"

# 3) バージョンゲート(3.10+)
if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,10) else 1)' 2>/dev/null; then
  die "Python ${MIN} 以上が必要です(検出: $("$PY" -V 2>&1 || echo 不明))。"
fi

# 4) UTF-8 を既定に(日本語/記号の出力崩れを防ぐ)
export PYTHONUTF8="${PYTHONUTF8:-1}"
export PYTHONIOENCODING="${PYTHONIOENCODING:-utf-8}"

# 5) 製品本体へ委譲(引数はそのまま渡す)
exec "$PY" -m dataplane "$@"
