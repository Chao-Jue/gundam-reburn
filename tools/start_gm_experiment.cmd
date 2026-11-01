@echo off
setlocal
set PILOT_EXTRA=%PILOT_EXTRA% --hangar-experiment gm
call "%~dp0start_local.cmd"
endlocal
