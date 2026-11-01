@echo off
REM ============================================================
REM  Experiment F : both records filled for the CURRENT world
REM  (troops=0 on both, real avatars). Tests whether the L0:0 kick
REM  is caused by the zeon record carrying troops=1.
REM  RUN AS ADMINISTRATOR. Oracle = the game screen.
REM ============================================================
setlocal
cd /d %~dp0..
set PILOT_EXTRA=--pilot-variants real_same_world
call %~dp0start_local.cmd
endlocal
