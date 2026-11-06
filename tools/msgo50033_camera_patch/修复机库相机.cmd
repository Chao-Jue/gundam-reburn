@echo off
chcp 936 >nul
setlocal
title 修复机库相机（等长改写，7 处）
echo ============================================================
echo   MSOL 机库相机注视点修复
echo ------------------------------------------------------------
echo   修的是「武器改造 / 强化」界面的相机：原来注视点算成 0，
echo   镜头一路往下看脚，所以又陡又矮。改成绝对高度后抬到胸部。
echo.
echo   只改 7 个脚本里的 41 个字节，文件长度不变，可随时还原。
echo   首次运行会生成 0000.dat.camera.bak
echo ============================================================
echo.
rem ---- 约定：本文件必须和 GundamOnline_CHINA.exe 放在同一目录 ----
if not defined MGOL_GAME set "MGOL_GAME=%~dp0"
if not exist "%MGOL_GAME%\GundamOnline_CHINA.exe" (
  echo [错误] 这个目录里没有 GundamOnline_CHINA.exe：
  echo        %MGOL_GAME%
  echo.
  echo        请把本文件复制到游戏根目录（和 GundamOnline_CHINA.exe 同一个文件夹）
  echo        再双击运行。
  echo.
  pause
  exit /b 1
)
echo 游戏目录：%MGOL_GAME%
set "PS1=%TEMP%\mgol_camera_patch.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$l=Get-Content -LiteralPath '%~f0' -Encoding Default;$i=[Array]::IndexOf($l,'==== PS_PAYLOAD_BEGIN ====');$p=$l[($i+1)..($l.Count-1)] -join [char]10;Set-Content -LiteralPath '%PS1%' -Value $p -Encoding Default"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
echo.
pause
exit /b
==== PS_PAYLOAD_BEGIN ====
$ErrorActionPreference = 'Stop'
# convention: this file sits next to GundamOnline_CHINA.exe; the cmd passes
# its own folder via %~dp0. MGOL_GAME only needed for a manual override.
$Game = $env:MGOL_GAME
if (-not $Game) { $Game = '.' }
$Game = $Game.TrimEnd('\')
$Dat = Join-Path $Game 'data\script\0000.dat'
if (-not (Test-Path -LiteralPath $Dat)) {
  Write-Host ''
  Write-Host '[FAIL] 0000.dat not found under:' $Game
  Write-Host '       Put this file in the same folder as GundamOnline_CHINA.exe'
  Write-Host '       and run it again.'
  exit 1
}
Write-Host ''
Write-Host '[1/4] target :' $Dat
$Backup = $Dat + '.camera.bak'
if (-not (Test-Path -LiteralPath $Backup)) {
  Copy-Item -LiteralPath $Dat -Destination $Backup -Force
  Write-Host '[2/4] backup :' $Backup
} else {
  Write-Host '[2/4] backup : already exists, keep as is ->' $Backup
}

# offset|size|oldhex|newhex
$Patch = @(
  "30146044|28|23E12AD612484918B106D984CADDA588417584D547CE952E23B55B20|23E12AD612484918B106D984CADDB88824759AD54ACE952E21B55B20|L03_WeaponWindow_Camera_01.nut"
  "30147740|30|244F73E9E7B7E78FB27422979F4C43FF42E3CDE81C3D33A524239E332086|244F73E9E7B7E78FB27422979F4C56FF25E3E3E81F3D33A5222399332086|L03_WeaponWindow_Camera_03.nut"
  "29959586|30|95FFFE4B178ADDB7713FF34E3CF3E146D4643FFC4D887EB687D3534DC579|95FFFE4B178ADDB7713FF34E3CF3F446B76455FC50887EB685D34E4DC579|L03_HangarMenu_Camera_01.nut"
  "29957904|30|689E02378515EC6A230D1088A9069B10E24D78D3B24F378099876A98ED87|689E02378515EC6A230D1088A906AE10C54D8ED3B54F378097876598ED87|L03_HangarMenu_04.nut"
  "30432164|30|7D2FDCFB433D096B3115E2D8D6BC65F88A0848A07E7CD2BBB228F372FF3B|7D2FDCFB433D096B3115E2D8D6BC78F86D085EA0817CD2BBB028EE72FF3B|Menu_Camera_Hangar_OverCustom_03.nut"
  "30434350|30|572766B28F9DA38813726EFBDE0D25C2C5374A332BE9E9C6F58D941E7578|572766B28F9DA38813726EFBDE0D38C2A83760332EE9E9C6F38D8F1E7578|Menu_Camera_Hangar_OverHaul_03.nut"
  "30430006|30|572766B28F9DA38813726EFBDE0D25C2C5374A332BE9E9C6F58D941E7578|572766B28F9DA38813726EFBDE0D38C2A83760332EE9E9C6F38D8F1E7578|Menu_Camera_Hangar_BuildupMsma_03.nut"
)

$fs = [System.IO.File]::Open($Dat, 'Open', 'ReadWrite', 'None')
try {
  $plan = @()
  foreach ($line in $Patch) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $f = $line.Split('|')
    $off = [int64]$f[0]
    $n   = [int]$f[1]
    $old = $f[2]
    $new = $f[3]
    $buf = New-Object byte[] $n
    $fs.Position = $off
    [void]$fs.Read($buf, 0, $n)
    $cur = ($buf | ForEach-Object { $_.ToString('X2') }) -join ''
    if ($cur -eq $new) {
      Write-Host ('        [skip] 0x{0:X} already patched ({1})' -f $off, $f[4])
      continue
    }
    if ($cur -ne $old) {
      Write-Host ('        [FAIL] 0x{0:X} mismatch ({1})' -f $off, $f[4])
      Write-Host '               current :' $cur
      Write-Host '               expect  :' $old
      Write-Host '       This client build differs. Nothing written.'
      exit 2
    }
    $plan += ,@($off, $n, $new, $f[4])
  }
  Write-Host ('[3/4] verified {0} / {1} site(s), nothing wrong' -f $plan.Count, $Patch.Count)
  foreach ($p in $plan) {
    $bytes = New-Object byte[] $p[1]
    for ($i = 0; $i -lt $p[1]; $i++) {
      $bytes[$i] = [Convert]::ToByte($p[2].Substring($i * 2, 2), 16)
    }
    $fs.Position = $p[0]
    $fs.Write($bytes, 0, $p[1])
    Write-Host ('        [ok] 0x{0:X} {1}' -f $p[0], $p[3])
  }
  $fs.Flush()
} finally {
  $fs.Close()
}

# read-back verify
$raw = [System.IO.File]::ReadAllBytes($Dat)
$bad = 0
foreach ($line in $Patch) {
  if ([string]::IsNullOrWhiteSpace($line)) { continue }
  $f = $line.Split('|')
  $off = [int64]$f[0]
  $n = [int]$f[1]
  $cur = ($raw[$off..($off + $n - 1)] | ForEach-Object { $_.ToString('X2') }) -join ''
  if ($cur -ne $f[3]) { $bad++; Write-Host ('        [BAD] 0x{0:X}' -f $off) }
}
Write-Host ''
if ($bad -eq 0) {
  Write-Host '[4/4] DONE. All sites verified by read-back.'
  Write-Host '      Restart the client (relog is NOT enough).'
} else {
  Write-Host ('[4/4] FAILED: {0} site(s) did not verify. Restore from:' -f $bad)
  Write-Host '      ' $Backup
  exit 3
}
