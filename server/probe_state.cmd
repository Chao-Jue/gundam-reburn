@echo off
chcp 65001 >nul
rem Right-click -> Run as administrator.
set PY=C:\Users\86186\.workbuddy\binaries\python\envs\default\Scripts\python.exe
set SC=D:\project\gundam-reburn\server\probe_state.py
"%PY%" "%SC%" --seconds 900
echo.
echo ---- done. log: D:\project\gundam-reburn\server\probe_state.log ----
pause
