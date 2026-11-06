@echo off
chcp 936 >nul
setlocal enableextensions
title MSGO 5.0.0.33 - 客户端启动（本地测试）

rem ============================================================
rem  机动战士敢达 Online 5.0.0.33 接入包启动入口
rem  本文件必须与 GundamOnline_CHINA.exe 在同一目录。
rem  服务端在 127.0.0.1:30000（由接入包的 data 文件指定），本机需先启动服务端。
rem  参数 ./data/ cpsoff：跳过 CPS 保护驱动，不加会弹「发现错误 / 49236」。
rem  补券逻辑已内嵌在本文件末尾，无额外补丁文件、无需联网。
rem ============================================================

set "GAME=%~dp0"
if exist "%GAME%GundamOnline_CHINA.exe" goto found
echo [错误] 找不到 GundamOnline_CHINA.exe。
echo        请把接入包内容整体复制到客户端主程序同一个文件夹里。
pause
exit /b 2

:found
cd /d "%GAME%"
tasklist /NH /FI "IMAGENAME eq GundamOnline_CHINA.exe" 2>nul | findstr /I "GundamOnline_CHINA.exe" >nul
if not errorlevel 1 goto running

echo ================================================
echo   MSGO 5.0.0.33 Launch（本地测试服务端 127.0.0.1:30000）
echo ================================================

rem ---- 防火墙放行（仅管理员时生效，失败不影响启动） ----
net session >nul 2>&1
if not errorlevel 1 (
    netsh advfirewall firewall show rule name="GundamOnline China in" >nul 2>&1
    if errorlevel 1 netsh advfirewall firewall add rule name="GundamOnline China in" dir=in action=allow program="%GAME%GundamOnline_CHINA.exe" enable=yes >nul 2>&1
    netsh advfirewall firewall show rule name="GundamOnline China out" >nul 2>&1
    if errorlevel 1 netsh advfirewall firewall add rule name="GundamOnline China out" dir=out action=allow program="%GAME%GundamOnline_CHINA.exe" enable=yes >nul 2>&1
)

echo [%date% %time%] 启动中...
start "" /d "%GAME%" "%GAME%GundamOnline_CHINA.exe" ./data/ cpsoff
ping -n 7 127.0.0.1 >nul
tasklist /NH /FI "IMAGENAME eq GundamOnline_CHINA.exe" 2>nul | findstr /I "GundamOnline_CHINA.exe" >nul
if errorlevel 1 goto failed

rem ---- [ticket-src] one-shot fill (payload embedded at end of this file) ----
set "PS1=%TEMP%\mgol_ticket_src.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$l=Get-Content -LiteralPath '%~f0' -Encoding Default;$i=[Array]::IndexOf($l,'==== PS_PAYLOAD_BEGIN ====');$p=$l[($i+1)..($l.Count-1)] -join [char]10;Set-Content -LiteralPath '%PS1%' -Value $p -Encoding Default"
set "MSGO_LOG=%GAME%ticket_src_patch.log"
start "MSGO ticket src" /min powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%"

echo.
echo [OK] 客户端已在运行；强化券数据已在后台自动填充，本窗口可以关闭。
ping -n 4 127.0.0.1 >nul
exit /b 0

:failed
echo.
echo [失败] 6 秒内没看到 GundamOnline_CHINA.exe 进程。
echo   1. 若弹「发现错误 / 内部错误码 49236」：说明 cpsoff 参数没带上，用本包的 cmd 启动。
echo   2. 也可右键本文件 -^> 以管理员身份运行再试。
pause
exit /b 1

:running
echo [提示] 客户端已在运行，不重复启动；补做一次券数据源填充。
rem ---- [ticket-src] one-shot fill (payload embedded at end of this file) ----
set "PS1=%TEMP%\mgol_ticket_src.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$l=Get-Content -LiteralPath '%~f0' -Encoding Default;$i=[Array]::IndexOf($l,'==== PS_PAYLOAD_BEGIN ====');$p=$l[($i+1)..($l.Count-1)] -join [char]10;Set-Content -LiteralPath '%PS1%' -Value $p -Encoding Default"
set "MSGO_LOG=%GAME%ticket_src_patch.log"
start "MSGO ticket src" /min powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%"

pause
exit /b 5

goto :eof
==== PS_PAYLOAD_BEGIN ====
$T=@(80100001,80200001,80300001,80400001,80500001,80600001,80700001,80800001,80900001,81000001,81100001)
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public class M{
[DllImport("kernel32.dll",SetLastError=true)]public static extern IntPtr OpenProcess(uint a,bool b,int p);
[DllImport("kernel32.dll",SetLastError=true)]public static extern bool ReadProcessMemory(IntPtr h,IntPtr a,byte[] b,int s,out int r);
[DllImport("kernel32.dll",SetLastError=true)]public static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[] b,int s,out int w);
[DllImport("kernel32.dll",SetLastError=true)]public static extern bool CloseHandle(IntPtr h);}
'@
function ReadMem([IntPtr]$h,[IntPtr]$a,[int]$n){$b=New-Object byte[] $n;$g=0;if(-not [M]::ReadProcessMemory($h,$a,$b,$n,[ref]$g)){return $null};if($g -lt $n){return $null};return ,$b}
$log=$env:MSGO_LOG;if(!$log){$log=Join-Path $env:TEMP 'ticket_src_patch.log'}
function LogIt($m){$s=(Get-Date -Format 'MM-dd HH:mm:ss')+' '+$m;try{Add-Content -LiteralPath $log -Value $s -Encoding UTF8}catch{};Write-Host $s}
LogIt '=== MGOL ticket-src patch (embedded one-click) ==='
$d=(Get-Date).AddSeconds(90);$ok=$false
while((Get-Date) -lt $d -and !$ok){
$p=Get-Process -Name GundamOnline_CHINA -ErrorAction SilentlyContinue|Sort-Object Id|Select-Object -First 1
if(!$p){Start-Sleep 2;continue}
$h=[M]::OpenProcess(0x0038,$false,$p.Id)
if($h -eq [IntPtr]::Zero){LogIt ('[RESULT] FAILED OpenProcess err='+[Runtime.InteropServices.Marshal]::GetLastWin32Error()+' (run cmd as admin)');$ok=$true;continue}
try{
$u=ReadMem $h ([IntPtr]0x1161F80) 4;if(!$u){Start-Sleep 2;continue}
$ui=[BitConverter]::ToUInt32($u,0);if(!$ui){Start-Sleep 2;continue}
$s=ReadMem $h ([IntPtr]([int64]$ui+0x50)) 4;if(!$s){Start-Sleep 2;continue}
$src=[BitConverter]::ToUInt32($s,0);if(!$src){Start-Sleep 2;continue}
$c=ReadMem $h ([IntPtr]([int64]$src)) 44;if(!$c){Start-Sleep 2;continue}
$nz=$false;foreach($x in $c){if($x){$nz=$true;break}}
if($nz){LogIt ('[RESULT] OK ready pid='+$p.Id);$ok=$true;continue}
$b=New-Object byte[] 44
for($i=0;$i -lt $T.Count;$i++){[Array]::Copy([BitConverter]::GetBytes([uint32]$T[$i]),0,$b,$i*4,4)}
$w=0
if(-not [M]::WriteProcessMemory($h,[IntPtr]([int64]$src),$b,44,[ref]$w)){LogIt ('[RESULT] FAILED Write err='+[Runtime.InteropServices.Marshal]::GetLastWin32Error());$ok=$true;continue}
$k=ReadMem $h ([IntPtr]([int64]$src)) 16
if($k -and [BitConverter]::ToUInt32($k,0) -eq $T[0]){LogIt ('[RESULT] OK filled 11 tickets pid='+$p.Id+' src=0x'+$src.ToString('X'));$ok=$true}else{LogIt '[RESULT] FAILED readback mismatch';$ok=$true}
}finally{[void][M]::CloseHandle($h)}
}
if(!$ok){LogIt '[RESULT] FAILED timeout (client not ready)'}
