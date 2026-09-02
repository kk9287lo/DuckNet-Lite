@echo off
REM ============================================================================
REM  DuckNet-Tray.bat - DuckNet-Lite: launch the system-tray icon (Windows)
REM  Double-click to run. Uses pythonw (no console window) when available.
REM  Right-click the tray icon for: Open dashboard / About / Free-tier features / Quit.
REM ============================================================================
cd /d "%~dp0"
where pythonw >nul 2>&1 && (start "" pythonw -m dataplane tray) || (start "" python -m dataplane tray)
