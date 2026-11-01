@echo off
setlocal
REM 用法：
REM   start_gm_experiment.cmd            老路线：frida 注入 + 伪造 CPS
REM   start_gm_experiment.cmd cpsoff     纯原生：带 cpsoff 跳过 ACOPCShell，无 frida、不需要管理员
if /I "%~1"=="cpsoff" set GUNDAM_CPS_OFF=1
set PILOT_EXTRA=%PILOT_EXTRA% --hangar-experiment gm
call "%~dp0start_local.cmd"
endlocal
