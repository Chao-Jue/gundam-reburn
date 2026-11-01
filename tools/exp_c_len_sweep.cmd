@echo off
REM ============================================================
REM  Experiment C : sweep ODD body lengths only (801..881, step 2).
REM  body = 2*L + 21  (always odd), so a wrong record stride shows up
REM  only on odd body lengths -- never tested before with valid data.
REM  One frame per candidate => no cross-frame residue.
REM  RUN AS ADMINISTRATOR. Oracle = the game screen.
REM ============================================================
setlocal
cd /d %~dp0..
set PILOT_EXTRA=--pilot-len-sweep 801-881 --probe-len-step 2 --probe-gap 0.6
call %~dp0start_local.cmd
endlocal
