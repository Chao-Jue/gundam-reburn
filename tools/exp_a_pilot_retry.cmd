@echo off
REM ============================================================
REM  Experiment A : resend the same 0xE13A body 3 times
REM  tests: is the first copy swallowed by a stale pending request?
REM  RUN AS ADMINISTRATOR. Oracle = the game screen.
REM ============================================================
setlocal
cd /d %~dp0..
set PILOT_EXTRA=--pilot-repeat 3 --pilot-repeat-gap 4
call %~dp0start_local.cmd
endlocal
