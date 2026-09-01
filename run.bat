@echo off
rem =============================================================================
rem DuckNet L7 Security - 起動ランチャ (Windows / cmd)
rem -----------------------------------------------------------------------------
rem 役割: Python を堅牢に検出し、バージョンを確認し、UTF-8 を整えて製品本体へ委譲する。
rem   run.bat                      ... ゲートウェイ(前衛 + 管理ダッシュボード)
rem   run.bat --help               ... 製品の全オプション
rem
rem 環境変数 / 設定:
rem   DUCKNET_PYTHON    使う Python を明示(未設定なら .venv -> py -3 -> python)
rem   DUCKNET_ENV_FILE  読み込む設定ファイル(既定: スクリプトと同じ場所の app.env)
rem 終了コード: 製品の終了コードをそのまま返す。起動前提を満たさない場合は 9。
rem =============================================================================
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul 2>&1
set "SELF=%~dp0"
pushd "%SELF%"

rem 1) 任意の設定ファイル(KEY=VALUE / # はコメント)
if not defined DUCKNET_ENV_FILE set "DUCKNET_ENV_FILE=%SELF%app.env"
if exist "%DUCKNET_ENV_FILE%" (
  for /f "usebackq eol=# tokens=1* delims==" %%A in ("%DUCKNET_ENV_FILE%") do (
    if not "%%A"=="" set "%%A=%%B"
  )
)

rem 2) Python を選ぶ: 明示 -> ローカル venv -> py -3 -> python
set "PY="
if defined DUCKNET_PYTHON set "PY=%DUCKNET_PYTHON%"
if not defined PY if exist "%SELF%.venv\Scripts\python.exe" set "PY=%SELF%.venv\Scripts\python.exe"
if not defined PY if exist "%SELF%venv\Scripts\python.exe"  set "PY=%SELF%venv\Scripts\python.exe"
if not defined PY ( where py >nul 2>&1 && set "PY=py -3" )
if not defined PY ( where python >nul 2>&1 && set "PY=python" )
if not defined PY (
  echo DuckNet: Python が見つかりません。Python 3.10+ を導入するか DUCKNET_PYTHON を設定してください。 1>&2
  popd & endlocal & exit /b 9
)

rem 3) バージョンゲート(3.10+)
%PY% -c "import sys;raise SystemExit(0 if sys.version_info[:2]>=(3,10) else 1)" >nul 2>nul
if errorlevel 1 (
  echo DuckNet: Python 3.10 以上が必要です。 1>&2
  popd & endlocal & exit /b 9
)

rem 4) UTF-8 を既定に
if not defined PYTHONUTF8 set "PYTHONUTF8=1"
if not defined PYTHONIOENCODING set "PYTHONIOENCODING=utf-8"

rem 5) 製品本体へ委譲(引数はそのまま渡す)
%PY% -m dataplane %*
set "RC=%ERRORLEVEL%"
popd & endlocal & exit /b %RC%
