@echo off
setlocal
title gundam-reburn launcher
REM ============================================================
REM  gundam-reburn : one-click local start
REM  RIGHT-CLICK -> "Run as administrator"
REM ============================================================
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

set ODS_LOG=server\ods_live.log

echo [i] project = %CD%
echo.

echo [i] 1/7 hosts guard ...
start "hosts-guard" /min "%PY%" tools\hosts_guard.py
timeout /t 2 /nobreak >nul

echo [i] 2/7 kill leftover client ...
taskkill /F /IM GundamOnline_CHINA.exe >nul 2>&1
timeout /t 1 /nobreak >nul

echo [i] 3/7 clean leftover CPS service ...
"%PY%" tools\clean_cps.py
timeout /t 1 /nobreak >nul

echo [i] 4/7 check hosts ...
findstr /C:"ms.patch1.9you.com" "%SystemRoot%\System32\drivers\etc\hosts" >nul 2>&1
if errorlevel 1 echo     [!] hosts entry missing - guard may lack admin rights
if not errorlevel 1 echo     [ok] hosts entry present

echo [i] 5/7 check ports 80 / 30000 ...
netstat -ano | findstr ":80 " | findstr LISTENING >nul 2>&1
if errorlevel 1 goto :start_http
echo     [ok] port 80 already running
goto :check_auth

:start_http
echo     [..] starting fake HTTP on 80 ...
start "fake-http" /min "%PY%" server\fake_http.py --host 127.0.0.1 --port 80
timeout /t 2 /nobreak >nul
netstat -ano | findstr ":80 " | findstr LISTENING >nul 2>&1
if errorlevel 1 echo     [!] port 80 STILL not listening - server list will be dummy
if not errorlevel 1 echo     [ok] port 80 started

:check_auth
echo     [..] kill stale listener on 30000 ...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":30000" ^| findstr LISTENING') do taskkill /F /PID %%p >nul 2>&1
timeout /t 1 /nobreak >nul

:start_auth
echo     [..] starting fake AUTH on 30000 ...
REM --idle 必须给大：到了机师阶段客户端会长时间不吐一行，300s 会把连接关掉
start "fake-auth" /min "%PY%" server\fake_auth.py --sweep --sweep-gap 2 --idle 7200 --seventye9 zero --pilot-variants vacant_both --probe-gap 12.0 %PILOT_EXTRA%
timeout /t 2 /nobreak >nul
echo     [ok] port 30000 started

:launch
echo [i] 6/7 start ODS listener and read-only state probe ...
REM DBWIN allows only one listener at a time - drop our previous instance first
taskkill /F /FI "WINDOWTITLE eq ods-listen*" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq pilot-state-probe*" >nul 2>&1
timeout /t 1 /nobreak >nul
set ODS_FORCE=
"%PY%" tools\ods_listen.py --check
if errorlevel 3 (
    echo     [!] another ODS listener is already attached
    echo         -^> starting anyway with --force; lines may be split between listeners
    set ODS_FORCE=--force
)
start "ods-listen" /min "%PY%" tools\ods_listen.py %ODS_FORCE% --pid-name GundamOnline_CHINA.exe --exit-with-process --wait-process-timeout 300 --seconds 3000 --file "%ODS_LOG%"
start "pilot-state-probe" /min "%PY%" tools\probe_pilot_state.py --pid-name GundamOnline_CHINA.exe --seconds 3000 --interval 0.05 --file server\pilot_state.log
timeout /t 2 /nobreak >nul
echo     [ok] ODS log -^> %ODS_LOG%
echo     [ok] state log -^> server\pilot_state.log
echo         client-side recv_pilot_list_get_r^( result=... will land here

echo [i] auto-advance (skip the stuck download queue so the step machine passes) ...
REM 为什么需要它：下载队列里最后一张 develop/mechanic_overcustom.csv (ID 67) 永远解析不成功
REM （2026-10-25 实测：正文换成 2B/7B/162B、8 行真数据都试过，表对象里始终 0 行 ⇒ Load 没跑），
REM 泵因此永远不置 done，步骤机 case 5 死等，界面停在「正在取得数据」。
REM auto_advance 把泵的 +0x0C 清零让 done 成立 —— 这是"绕过"，不是"修复"。
REM 想复现"自然走完要多久卡住"时用: set GUNDAM_AUTO_ADVANCE=0
if "%GUNDAM_AUTO_ADVANCE%"=="0" (
    echo     [i] auto-advance DISABLED - the client will stall at "loading data"
) else (
    start "auto-advance" /min "%PY%" tools\auto_advance.py
    timeout /t 1 /nobreak >nul
    echo     [ok] auto-advance ON ^(writes 4 bytes: pump+0x0C = 0^)
)
echo [i] 7/7 launching client ...
echo.
echo     After the client is up, optionally run start_msgid.cmd (as admin)
echo     to attach the msg-id probe.
echo.

"%PY%" tools\run_hooked.py --no-elevate --fake all --redirect-connect 127.0.0.1:30000 --out-file server\hook_runs\_pilot_run.log --retry 10 --seconds 3000 --veh
echo.
echo [i] client exited (code=%errorlevel%)

:end
REM stop the ODS listener so it never lingers as a second listener
taskkill /F /FI "WINDOWTITLE eq ods-listen*" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq pilot-state-probe*" >nul 2>&1
echo.
echo [i] ODS log: %CD%\%ODS_LOG%
if exist "%ODS_LOG%" (
    findstr /C:"recv_pilot_list_get_r" "%ODS_LOG%" >nul 2>&1
    if not errorlevel 1 (
        echo     [!!] FOUND recv_pilot_list_get_r - handler reached the success path
    ) else (
        echo     [--] no recv_pilot_list_get_r line - handler never got there
    )
) else (
    echo     [--] ODS log was not created - listener did not run
)
echo.
echo [i] press any key to close this window.
pause >nul
endlocal
