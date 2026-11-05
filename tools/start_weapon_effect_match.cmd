@echo off
setlocal
cd /d "%~dp0.."
set "PY=C:\Users\86186\.workbuddy\binaries\python\envs\default\Scripts\python.exe"
if exist "%PY%" goto runtime_ready
set "PY=python"
:runtime_ready
"%PY%" -c "import numpy, PIL" >nul 2>&1
if errorlevel 1 goto missing_dependencies
echo Starting weapon effect matcher on http://127.0.0.1:8769
echo Close this window to stop it. Manual assignments are kept in
echo server\reference\weapon_effect_match\weapon_effect_assignments.json
"%PY%" tools\weapon_effect_match.py --port 8769 --open %*
if errorlevel 1 goto failed
exit /b 0

:missing_dependencies
echo Python or dependencies are unavailable. Install Python and run:
echo python -m pip install Pillow numpy
pause
exit /b 1

:failed
echo The matcher exited with an error. See the message above.
pause
exit /b 1
