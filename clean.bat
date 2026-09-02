@echo off
REM ============================================================================
REM  clean.bat - DuckNet-Lite: pre-GitHub-upload cleanup (Windows)
REM  Removes ONLY build artifacts / caches. Keeps source, ico/ images,
REM  app.env and .git. Same targets as .gitignore. Double-clickable.
REM ============================================================================
setlocal EnableExtensions
cd /d "%~dp0"
echo [DuckNet-Lite] cleanup in "%cd%"

REM --- Python bytecode caches (recursively remove __pycache__ dirs) ---
for /d /r %%d in (__pycache__) do if exist "%%d" rd /s /q "%%d"

REM --- compiled Python ---
del /s /q *.pyc *.pyo *.pyd >nul 2>&1

REM --- test / type / lint / coverage / build artifacts ---
for /d /r %%d in (.pytest_cache .mypy_cache .ruff_cache htmlcov) do if exist "%%d" rd /s /q "%%d"
for /d /r %%d in (*.egg-info) do if exist "%%d" rd /s /q "%%d"
if exist build rd /s /q build
if exist dist  rd /s /q dist
del /q .coverage >nul 2>&1

REM --- logs (*.log is untracked per .gitignore) ---
del /s /q *.log >nul 2>&1

REM --- OS / editor cruft ---
del /s /q /a:h .DS_Store Thumbs.db desktop.ini >nul 2>&1
del /s /q *.swp *~ >nul 2>&1

REM NOTE: app.env / .claude\launch.json are the operator's local settings and are
REM       NOT deleted (already gitignored, so they never reach Git). ico/ + assets kept.

echo [DuckNet-Lite] done. Only files the repo needs remain.
endlocal
