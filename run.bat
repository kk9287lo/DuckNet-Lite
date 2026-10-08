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
rem NOTE: delayed expansion stays OFF on purpose. The app.env loop below does
rem   set "%%A=%%B", and with delayed expansion any "!" inside a value is eaten.
rem   Only the quote-stripping step turns it on locally, after the raw value is set,
rem   and hands the result back through FOR so that "!" survives.
rem NOTE: avoid "call :label" / "goto" here. With "chcp 65001" and this UTF-8 file, cmd
rem   can lose its read position after a jump and run pieces of comments as commands.
setlocal EnableExtensions DisableDelayedExpansion
set _DN_DQ=^"
chcp 65001 >nul 2>&1
set "SELF=%~dp0"
pushd "%SELF%"

rem 1) 任意の設定ファイル(KEY=VALUE / # はコメント)
rem    Values are trimmed and one pair of matching surrounding quotes (" or ') is
rem    dropped, the same rule as dataplane.service.load_env_file. A value set here wins
rem    over the product's own parsing, so quotes used to leak into paths and tokens.
if not defined DUCKNET_ENV_FILE set "DUCKNET_ENV_FILE=%SELF%app.env"
if exist "%DUCKNET_ENV_FILE%" (
  for /f "usebackq eol=# tokens=1* delims==" %%A in ("%DUCKNET_ENV_FILE%") do (
    rem 既に環境にある値は上書きしない(呼び出し時の指定が常に勝つ)
    if not "%%A"=="" if not defined %%A (
      set "%%A=%%B"
      setlocal EnableDelayedExpansion
      set "_v=!%%A!"
      for /l %%i in (1,1,32) do if defined _v if "!_v:~0,1!"==" " set "_v=!_v:~1!"
      for /l %%i in (1,1,32) do if defined _v if "!_v:~-1!"==" " set "_v=!_v:~0,-1!"
      set "_q="
      if defined _v if not "!_v:~1!"=="" if "!_v:~0,1!"=="!_v:~-1!" set "_q=!_v:~0,1!"
      if "!_q!"=="'" set "_v=!_v:~1,-1!"
      if "!_q!"=="!_DN_DQ!" set "_v=!_v:~1,-1!"
      if defined _v (
        for /f delims^=^ eol^= %%V in ("!_v!") do endlocal & set "%%A=%%V"
      ) else (
        endlocal & set "%%A="
      )
    )
  )
)
set "_DN_DQ="

rem 2) Python を選ぶ: 明示 -> ローカル venv -> py -3 -> python
rem    PY is one executable and is always used quoted ("%PY%"), so paths with spaces work.
rem    Quotes written around DUCKNET_PYTHON (env or app.env) are dropped first.
set "PY="
set "PYARG="
if defined DUCKNET_PYTHON set "PY=%DUCKNET_PYTHON:"=%"
if not defined PY if exist "%SELF%.venv\Scripts\python.exe" set "PY=%SELF%.venv\Scripts\python.exe"
if not defined PY if exist "%SELF%venv\Scripts\python.exe"  set "PY=%SELF%venv\Scripts\python.exe"
if not defined PY ( where py >nul 2>&1 && set "PY=py" && set "PYARG=-3" )
if not defined PY ( where python >nul 2>&1 && set "PY=python" )
if not defined PY (
  echo DuckNet: Python が見つかりません。Python 3.10+ を導入するか DUCKNET_PYTHON を設定してください。 1>&2
  popd & endlocal & exit /b 9
)

rem 3) バージョンゲート(3.10+)
"%PY%" %PYARG% -c "import sys;raise SystemExit(0 if sys.version_info[:2]>=(3,10) else 1)" >nul 2>nul
if errorlevel 1 (
  echo DuckNet: Python 3.10 以上が必要です。 1>&2
  popd & endlocal & exit /b 9
)

rem 4) UTF-8 を既定に
if not defined PYTHONUTF8 set "PYTHONUTF8=1"
if not defined PYTHONIOENCODING set "PYTHONIOENCODING=utf-8"

rem 5) 製品本体へ委譲(引数はそのまま渡す)
"%PY%" %PYARG% -m dataplane %*
set "RC=%ERRORLEVEL%"
popd & endlocal & exit /b %RC%
