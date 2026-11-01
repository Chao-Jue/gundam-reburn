@echo off
REM ============================================================
REM  Experiment D : sweep the SHORT body range (401..799, step 2).
REM  body = 2*L + 21 (always odd).  Covers record stride L = 190..389,
REM  i.e. the range that the earlier sweeps (800..905) never touched.
REM  RUN AS ADMINISTRATOR. Oracle = the game screen / cnt_e13a.
REM ============================================================
setlocal
cd /d %~dp0..
set PILOT_EXTRA=--pilot-len-sweep 401-799 --probe-len-step 2 --probe-gap 0.35
call %~dp0start_local.cmd
endlocal
