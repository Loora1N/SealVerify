@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Python environment missing. Please follow README.md to install.
  pause
  exit /b 1
)
if "%~1"=="" (
  ".venv\Scripts\python.exe" -m sealverify view
) else (
  ".venv\Scripts\python.exe" -m sealverify view "%~1"
)
if errorlevel 1 pause
