@echo off
REM ============================================================
REM  Experiment E : BOTH pilot records filled with legal avatar data.
REM  real_eff  leaves the zeon record all-zero (avatar_id=0); the record
REM  parser bounds/validates field by field and returns false silently,
REM  which would explain why NO body length ever worked.
REM  RUN AS ADMINISTRATOR. Oracle = the game screen / cnt_e13a.
REM ============================================================
setlocal
cd /d %~dp0..
set PILOT_EXTRA=--pilot-variants real_both
call %~dp0start_local.cmd
endlocal
