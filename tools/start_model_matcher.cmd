@echo off
setlocal
cd /d "%~dp0.."
set "PY=C:\Users\86186\.workbuddy\binaries\python\envs\default\Scripts\python.exe"
if not exist "%PY%" (
  echo Python runtime not found. See tools/model_matcher/README.md
  pause
  exit /b 1
)
"%PY%" tools\model_matcher\app.py --open
if errorlevel 1 pause
endlocal
