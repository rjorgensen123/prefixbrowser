@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 nbprefix.py %*
) else (
  python nbprefix.py %*
)
if errorlevel 1 pause
