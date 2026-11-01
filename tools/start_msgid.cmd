@echo off
REM ============================================================
REM  Attach the msg-id probe to an ALREADY RUNNING client.
REM  RIGHT-CLICK -> "Run as administrator"
REM
REM  Why a separate file: injecting during client startup makes
REM  the Themida shell kill the process (we saw it crash every
REM  time when the probe was launched together with the client).
REM  So: start the client first, wait until the login screen is
REM  fully up, THEN run this file.
REM ============================================================
cd /d "%~dp0.."

set PY=C:\Users\86186\.workbuddy\binaries\python\envs\default\Scripts\python.exe

echo [i] attaching msgid probe (waits 3s then hooks 0x7d5009) ...
echo [i] log: server\msgid.log
echo.
echo     After you see "[+] hooked", go back to the game and log in.
echo.

"%PY%" tools\hook_msgid.py --follow --delay 3

echo.
echo [i] probe exited. press any key to close.
pause >nul
