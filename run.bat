@echo off
rem =============================================================================
rem DuckNet L7 Security - launcher (Windows / cmd)
rem -----------------------------------------------------------------------------
rem Role: find Python robustly, check its version, set up UTF-8, then hand over to the product.
rem   run.bat                      ... gateway (front proxy + admin dashboard)
rem   run.bat --help               ... all product options
rem
rem Environment variables / settings:
rem   DUCKNET_PYTHON    the Python to use (if unset: .venv -> py -3 -> python)
rem   DUCKNET_ENV_FILE  settings file to read (default: app.env next to this script)
rem Exit code: the product's exit code as is; 9 if a startup prerequisite is not met.
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

rem 1) Optional settings file (KEY=VALUE / # starts a comment)
rem    Values are trimmed and one pair of matching surrounding quotes (" or ') is
rem    dropped, the same rule as dataplane.service.load_env_file. A value set here wins
rem    over the product's own parsing, so quotes used to leak into paths and tokens.
if not defined DUCKNET_ENV_FILE set "DUCKNET_ENV_FILE=%SELF%app.env"
if exist "%DUCKNET_ENV_FILE%" (
  for /f "usebackq eol=# tokens=1* delims==" %%A in ("%DUCKNET_ENV_FILE%") do (
    rem Never overwrite a value already in the environment (a value given by the caller always wins)
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

rem 2) Choose Python: explicit -> local venv -> py -3 -> python
rem    DUCKNET_PYTHON (env or app.env) is read in one of two ways:
rem    - If the value with its quotes removed names an existing file, it is one executable and
rem      is run quoted, so a path with spaces works with or without quotes around it.
rem    - Otherwise it is a command line such as py -3 / py -3.12 / a quoted path followed by
rem      arguments, and is run as written (quotes included), as earlier releases did.
rem    PYRUN is the command prefix used below. The raw value is copied through FOR with delayed
rem    expansion on, so "&", ")" and "!" inside it are never parsed as batch syntax.
set "PY="
set "PYARG="
set "PYRUN="
set "_DN_CMD="
if defined DUCKNET_PYTHON set "PY=%DUCKNET_PYTHON:"=%"
if defined PY if not exist "%PY%" set "_DN_CMD=1"
if defined _DN_CMD setlocal EnableDelayedExpansion
if defined _DN_CMD for /f delims^=^ eol^= %%V in ("!DUCKNET_PYTHON!") do endlocal & set "PYRUN=%%V"
set "_DN_CMD="
if not defined PY if exist "%SELF%.venv\Scripts\python.exe" set "PY=%SELF%.venv\Scripts\python.exe"
if not defined PY if exist "%SELF%venv\Scripts\python.exe"  set "PY=%SELF%venv\Scripts\python.exe"
if not defined PY ( where py >nul 2>&1 && set "PY=py" && set "PYARG=-3" )
if not defined PY ( where python >nul 2>&1 && set "PY=python" )
if not defined PY (
  echo DuckNet: Python が見つかりません。Python 3.10+ を導入するか DUCKNET_PYTHON を設定してください。 1>&2
  popd & endlocal & exit /b 9
)
if not defined PYRUN set PYRUN="%PY%" %PYARG%

rem 3) Version gate (3.10+). "Too old" (10) and "cannot start" (9009 etc.) get different messages.
%PYRUN% -c "import sys;raise SystemExit(0 if sys.version_info[:2]>=(3,10) else 10)" >nul 2>nul
set "PYRC=%ERRORLEVEL%"
if "%PYRC%"=="10" (
  echo DuckNet: Python 3.10 以上が必要です。新しい Python を導入するか、DUCKNET_PYTHON で 3.10 以上の Python を指定してください。 1>&2
  popd & endlocal & exit /b 9
)
if not "%PYRC%"=="0" (
  if defined DUCKNET_PYTHON echo DuckNet: DUCKNET_PYTHON に指定された Python を起動できません。値を確認してください: python.exe のパス、または py -3 のようなコマンド。 1>&2
  if not defined DUCKNET_PYTHON echo DuckNet: Python を起動できません。Python 3.10+ を導入し直すか、DUCKNET_PYTHON で使う Python を指定してください。 1>&2
  popd & endlocal & exit /b 9
)

rem 4) Make UTF-8 the default
if not defined PYTHONUTF8 set "PYTHONUTF8=1"
if not defined PYTHONIOENCODING set "PYTHONIOENCODING=utf-8"

rem 5) Hand over to the product (arguments are passed through as is)
%PYRUN% -m dataplane %*
set "RC=%ERRORLEVEL%"
popd & endlocal & exit /b %RC%
