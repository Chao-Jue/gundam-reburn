@echo off
setlocal
cd /d "%~dp0.."
if errorlevel 1 (
    echo [!] cannot cd to project root
    goto :end
)
set PY=C:\Users\86186\.workbuddy\binaries\python\envs\default\Scripts\python.exe
if not exist "%PY%" (
    echo [!] python not found: %PY%
    goto :end
)
echo [i] launching read-only probe elevated (UAC once) ...
powershell -NoProfile -Command "Start-Process -FilePath '%PY%' -ArgumentList 'tools\\probe_pilot_state.py','--seconds','900','--file','server\\pilot_state.log' -Verb RunAs -WindowStyle Minimized"
echo [i] probe log = %CD%\server\pilot_state.log
echo [i] now start tools\start_local.cmd (as administrator) and let it run.
pause >nul
:end
endlocal
