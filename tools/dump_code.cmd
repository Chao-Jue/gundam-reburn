@echo off
REM ============================================================
REM  Read-only memory dump of the client's unpacked code.
REM  RIGHT-CLICK -> "Run as administrator"
REM
REM  Does NOT install any hook (pure readByteArray), so the
REM  Themida integrity check will not notice.
REM  Run this AFTER the client is fully up at the login screen.
REM ============================================================
cd /d "%~dp0.."

set PY=C:\Users\86186\.workbuddy\binaries\python\envs\default\Scripts\python.exe

echo [i] dumping 0x7d4000-0x7d5200 (9 x 512B) ...
"%PY%" tools\dump_code.py --follow --rva 0x7d4000,0x7d4200,0x7d4400,0x7d4600,0x7d4800,0x7d4a00,0x7d4c00,0x7d4e00,0x7d5000 --len 512 --out server\code_dump.json

echo.
echo [i] done. press any key to close.
pause >nul
