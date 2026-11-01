@echo off
REM ============================================================
REM  gundam-reburn : disable hypervisor + fast startup
REM  Run this AS ADMINISTRATOR (right click -> Run as administrator)
REM
REM  Why: the client is wrapped in Themida. Themida's anti-VM check
REM  reads CPUID.1:ECX bit31. This machine exposes a hypervisor
REM  (VBS / VirtualMachinePlatform are on), so the client refuses
REM  to start with "cannot run under a Virtual Machine".
REM
REM  Rollback:
REM    bcdedit /set hypervisorlaunchtype auto
REM    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 1 /f
REM ============================================================
setlocal
title gundam-reburn - disable hypervisor

net session >nul 2>&1
if errorlevel 1 (
    echo [X] NOT elevated. Right click this file and pick "Run as administrator".
    echo.
    pause
    exit /b 1
)

echo ============================================================
echo  [1/5] current BCD state
echo ============================================================
bcdedit /enum {current} | findstr /i "hypervisorlaunchtype"
if errorlevel 1 echo     ^(no hypervisorlaunchtype line = default/Auto^)

echo.
echo ============================================================
echo  [2/5] bcdedit /set hypervisorlaunchtype off
echo ============================================================
bcdedit /set hypervisorlaunchtype off
echo     exitcode = %errorlevel%

echo.
echo ============================================================
echo  [3/5] disable Fast Startup (HiberbootEnabled = 0)
echo ============================================================
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f

echo.
echo ============================================================
echo  [4/5] verify
echo ============================================================
bcdedit /enum {current} | findstr /i "hypervisorlaunchtype"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled

echo.
echo ============================================================
echo  [5/5] DONE - now you MUST do a REAL RESTART
echo ============================================================
echo.
echo   Use the Restart button, or run:   shutdown /r /t 0
echo.
echo   DO NOT use "shutdown then power on" - with Fast Startup that
echo   resumes the saved session and the hypervisor setting is ignored.
echo.
echo   After the restart, verify with:
echo       python tools\env_check.py
echo.
pause
endlocal
