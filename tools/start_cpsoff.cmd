@echo off
setlocal
title gundam-reburn  -  cpsoff (no CPS)
REM ============================================================
REM  One-click launcher: fake servers + client started with "cpsoff".
REM
REM  Why it works: before loading ACOPCShell.dll the client (0x5836xx)
REM  scans its command line; any argument starting with "cpsoff" sets
REM  [0x117B7A0]=1 and returns early, so the anti-cheat never loads.
REM  Result: no frida injection, no CPS IOCTL faking, no admin needed.
REM  Detail: server/cpsoff-验证-2026-11-01.md
REM
REM  Hangar data: GM experiment store is ON by default. The normal store
REM  (server/saved_hangar.json) does not exist on this machine, so a plain
REM  launch shows no unit at all. Same effect as start_gm_experiment.cmd.
REM
REM  Usage:  double-click this file     (= start_gm_experiment.cmd cpsoff)
REM          start_cpsoff.cmd plain     GM experiment OFF (normal assets)
REM ============================================================
cd /d "%~dp0.."

REM The client re-launches itself elevated, so this script cannot kill it.
REM Ask the user to close it first; otherwise the new instance is refused by
REM the single-instance mutex and the launcher looks like it did nothing.
tasklist /FI "IMAGENAME eq GundamOnline_CHINA.exe" /NH 2>nul | findstr /I "GundamOnline_CHINA.exe" >nul
if not errorlevel 1 (
    echo [!] GundamOnline_CHINA.exe is still running.
    echo     Close it first - it runs elevated and this script cannot kill it.
    echo     Or run this in another window ^(one UAC prompt^):
    echo       python tools\elevate_run.py --out server\hook_runs\_kill.out -- taskkill /F /IM GundamOnline_CHINA.exe
    echo.
    pause
    exit /b 4
)

set GUNDAM_CPS_OFF=1
set GM_MODE=gm
if /I "%~1"=="plain" set GM_MODE=off
if /I "%GM_MODE%"=="gm" set PILOT_EXTRA=%PILOT_EXTRA% --hangar-experiment gm

echo [i] launch mode: cpsoff  (no frida / no CPS faking / no admin)
echo [i] hangar experiment: %GM_MODE%
echo.
call "%~dp0start_local.cmd"
endlocal
