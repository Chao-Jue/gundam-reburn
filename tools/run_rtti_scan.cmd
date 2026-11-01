@echo off
REM ============================================================
REM  gundam-reburn : 只读侦察 —— 扫客户端内存里的 RTTI 类名
REM  双击本文件即可（会自动请求管理员权限）。
REM  跑完日志：
REM    server\hook_log.txt        全部 hook 事件
REM    server\hook_runs\rtti_scan.json   类名扫描结果（完整）
REM ============================================================
setlocal
title gundam-reburn - RTTI scan

net session >nul 2>&1
if errorlevel 1 (
    echo [*] 需要管理员权限，正在重新以管理员身份启动本脚本……
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)

cd /d "%~dp0.."

set "PY=C:\Users\86186\.workbuddy\binaries\python\envs\default\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

echo ============================================================
echo  [1/2] 清理上一轮的 CPS 残留
echo ============================================================
"%PY%" tools\clean_cps.py

echo.
echo ============================================================
echo  [2/2] 启动客户端 + 第 25 秒扫描 RTTI（观察 110 秒）
echo       *** 客户端窗口会自己弹出，本轮不用操作它 ***
echo ============================================================
"%PY%" tools\run_hooked.py --fake startService,openDevice,deviceIo,shell ^
    --seconds 110 --retry 6 --scan-rtti 25 --veh

echo.
echo ============================================================
echo  完成。结果在这里：
echo    server\hook_runs\rtti_scan.json
echo    server\hook_log.txt
echo ============================================================
pause
endlocal
