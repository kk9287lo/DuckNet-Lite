#!/usr/bin/env bash
# =============================================================================
# DuckNet L7 Security — 起動ランチャ (POSIX / Linux・macOS)
# -----------------------------------------------------------------------------
# 役割: Python を堅牢に検出し、バージョンを確認し、UTF-8 を整えて製品本体へ委譲する。
#   ./run.sh                      … ゲートウェイ(前衛 + 管理ダッシュボード)
#   ./run.sh --help               … 製品の全オプション
#
# 環境変数 / 設定:
#   DUCKNET_PYTHON    使う Python を明示(未設定なら .venv → python3 → python)
#   DUCKNET_ENV_FILE  読み込む設定ファイル(既定: スクリプトと同じ場所の app.env)
# 終了コード: 製品の終了コードをそのまま返す。起動前提を満たさない場合は 9。
# =============================================================================
set -euo pipefail

readonly MIN="3.10"
SELF="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" >/dev/null 2>&1 && pwd)"
cd "$SELF"

die() { printf 'DuckNet: %s\n' "$*" >&2; exit 9; }

# 1) 任意の設定ファイル(KEY=VALUE・# はコメント)。source せず安全に取り込む。
# 製品側の設定は Python(dataplane.service.load_env_file)が同じファイルを読むので、
# ここで拾うのは *シェル自身が使う* DUCKNET_PYTHON 等だけでよい。
# 旧実装は set -e 下で `export "$key=$val"` していたため、`KEY = value` のように = の
# 前後へ空白を入れただけでランチャごと起動不能になっていた("not a valid identifier")。
# 既に環境にある値は上書きしない(呼び出し時の指定が常に勝つ)。
ENV_FILE="${DUCKNET_ENV_FILE:-$SELF/app.env}"
if [ -f "$ENV_FILE" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"                       # CRLF 保存された場合の \r を落とす
    line="${line#"${line%%[![:space:]]*}"}"     # 先頭の空白(字下げ)
    case "$line" in ''|\#*) continue ;; esac    # 空行・コメント
    case "$line" in *=*) ;; *) continue ;; esac
    key="${line%%=*}"; val="${line#*=}"
    key="${key%"${key##*[![:space:]]}"}"        # キー末尾の空白
    val="${val#"${val%%[![:space:]]*}"}"        # 値先頭の空白
    val="${val%"${val##*[![:space:]]}"}"        # 値末尾の空白
    case "$key" in ''|*[!A-Za-z0-9_]*) continue ;; esac   # 不正キーは飛ばす
    [ -n "${!key+x}" ] && continue              # 呼び出し時の指定を優先
    export "$key=$val"
  done < "$ENV_FILE"
fi

# 2) Python を選ぶ: 明示 → ローカル venv → python3 → python
pick_python() {
  if [ -n "${DUCKNET_PYTHON:-}" ]; then printf '%s' "$DUCKNET_PYTHON"; return 0; fi
  local c
  for c in "$SELF/.venv/bin/python" "$SELF/venv/bin/python" python3 python; do
    if command -v "$c" >/dev/null 2>&1; then printf '%s' "$c"; return 0; fi
  done
  return 1
}
PY="$(pick_python)" || die "Python が見つかりません。Python ${MIN}+ を導入するか DUCKNET_PYTHON を設定してください。"
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
