@echo off
REM ============================================================
REM  Experiment B : auto-advance OFF + resend each 0x5290 3 times
REM  tests: can the download pump ever drain by itself?
REM  RUN AS ADMINISTRATOR. Oracle = a 66th 0xF86A line in
REM  server\fake_auth.log (watch ~60s after table 65).
REM ============================================================
setlocal
cd /d %~dp0..
set GUNDAM_AUTO_ADVANCE=0
set PILOT_EXTRA=--dl-retry 3 --dl-retry-gap 1.5
call %~dp0start_local.cmd
endlocal
