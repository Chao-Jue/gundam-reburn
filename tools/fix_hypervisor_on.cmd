@echo off
REM ============================================================
REM  gundam-reburn : RESTORE hypervisor (enable WSL2 / VBS / Sandbox)
REM  Run this AS ADMINISTRATOR (right click -> Run as administrator)
REM
REM  This undoes tools\fix_hypervisor_off.cmd.
REM  After running, you MUST do a REAL RESTART (Restart button, or
REM  "shutdown /r /t 0").  "Shutdown then power on" will NOT work
REM  while Fast Startup is enabled.
REM ============================================================
setlocal
title gundam-reburn - restore hypervisor

net session >nul 2>&1
if errorlevel 1 (
    echo [X] NOT elevated. Right click this file and pick "Run as administrator".
    echo.
    pause
    exit /b 1
)

echo ============================================================
echo  [1/4] current BCD state
echo ============================================================
bcdedit /enum {current} | findstr /i "hypervisorlaunchtype"
if errorlevel 1 echo     ^(no hypervisorlaunchtype line = default / Auto^)

echo.
echo ============================================================
echo  [2/4] bcdedit /set hypervisorlaunchtype auto
echo ============================================================
bcdedit /set hypervisorlaunchtype auto
echo     exitcode = %errorlevel%

echo.
echo ============================================================
echo  [3/4] verify
echo ============================================================
bcdedit /enum {current} | findstr /i "hypervisorlaunchtype"
if errorlevel 1 echo     ^(no line = default / Auto  ^<-- this is what we want^)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled

echo.
echo ============================================================
echo  [4/4] DONE - now do a REAL RESTART
echo ============================================================
echo.
echo   Restart button, or:   shutdown /r /t 0
echo.
echo   After the restart, verify with:
echo       python tools\env_check.py
echo   Expect: CPUID.1:ECX bit31 = 1  (hypervisor visible again)
echo.
echo   NOTE: once the hypervisor is back, the game client will refuse
echo   to start again (Themida anti-VM).  To play again, re-run
echo   tools\fix_hypervisor_off.cmd + real restart.
echo.
pause
endlocal
