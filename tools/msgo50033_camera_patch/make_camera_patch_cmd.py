# -*- coding: utf-8 -*-
"""生成「修复机库相机.cmd」：把已在本机做好的等长改写，浓缩成 7 条定点字节写入。

为什么不用传 33MB：
    这次只有 41 个字节变了（每处 `height *= 0.55;` -> `height = 63.30;`，
    UTF-16 里每个字符只动低字节），所以远端只需要「绝对偏移 + 原密文 + 新密文」。
    补丁文件约 5.6KB，零依赖（不需要 fpmf.py / Python / 密钥表）。

输入：
    patch_script_camera.py --apply 生成的备份目录（camera_<时间戳>/0000.dat + meta.json）
    当前已打补丁的 data/script/0000.dat
输出：
    <out-dir>/修复机库相机.cmd       GBK + 全 CRLF，payload 全 ASCII
    <out-dir>/camera_patch.json      给程序读的同一份数据

安全设计：
    * 先备份 0000.dat.camera.bak（只在不存在时创建，保留最初原始档）；
    * 每处写入前校验「当前字节 == 原密文」，不匹配就整体中止（版本不同 / 已改过）；
    * 已等于新密文的算「已打过」，跳过；写完逐处回读校验；
    * cmd 用 %~dp0 自定位，放错目录会中文报错退出且不写任何字节。

用法：
    python make_camera_patch_cmd.py --game "<游戏根目录>" \
        --fpmf-dir "<含 fpmf.py 的目录>" \
        --backup-root "./_msgo_camera_backup" --out-dir "./camera-patch-dist"

生成的 cmd 只适用于**产生这份备份的同一个客户端 build**（偏移与密文硬绑定）。
换版本请重新跑两个脚本生成，不要直接复用。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MARK = "==== PS_PAYLOAD_BEGIN ===="


def load_fpmf(fpmf_dir: str | None):
    if fpmf_dir:
        sys.path.insert(0, str(Path(fpmf_dir).resolve()))
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    try:
        import fpmf
    except ImportError as e:
        raise SystemExit("缺少 fpmf.py：放到本脚本同目录、或用 --fpmf-dir 指定。%s" % e)
    return fpmf


def resolve_game(arg: str | None) -> Path:
    cands = [Path(arg).resolve()] if arg else [Path.cwd(), HERE, HERE.parent, HERE.parent.parent]
    for p in cands:
        if (p / "GundamOnline_CHINA.exe").is_file():
            return p
    raise SystemExit("找不到游戏根目录（含 GundamOnline_CHINA.exe），请用 --game 指定。")


def newest_backup(root: Path) -> Path:
    if not root.is_dir():
        raise SystemExit("备份根目录不存在：%s" % root)
    dirs = sorted((d for d in root.iterdir()
                   if d.is_dir() and d.name.startswith("camera_")), reverse=True)
    if not dirs:
        raise SystemExit("%s 里没有 camera_* 备份目录，先跑 patch_script_camera.py --apply" % root)
    return dirs[0]


def build_entries(game: Path, backup: Path, fpmf, key_bin: str | None) -> list[dict]:
    meta = json.loads((backup / "meta.json").read_text(encoding="utf-8"))
    key_cands = [game / "GundamOnline_CHINA.exe"]
    if key_bin:
        key_cands.insert(0, Path(key_bin))
    keys = fpmf.load_keys(*key_cands)
    archive = fpmf.parse_hed(game / "data" / "script.hed", keys,
                            data_root=game / "data")
    dat = game / "data" / "script" / "0000.dat"
    old_raw = (backup / "0000.dat").read_bytes()
    new_raw = dat.read_bytes()

    by_name = {r.logical_path.replace("\\", "/").split("/")[-1]: r
               for r in archive.records}

    entries = []
    for item in meta["records"]:
        name = item["name"]
        rec = by_name.get(name)
        if rec is None:
            raise SystemExit("索引里找不到 %s" % name)
        plain = fpmf.read_resource(archive, rec, keys)
        needle = item["new"].encode("utf-16-le")
        idx = plain.find(needle)
        if idx < 0:
            raise SystemExit("%s 里找不到新串（是不是又改回去了？）" % name)
        n = len(needle)
        dat_off = rec.offset + idx
        entries.append({
            "name": name,
            "dat_offset": dat_off,
            "size": n,
            "old_hex": old_raw[dat_off:dat_off + n].hex().upper(),
            "new_hex": new_raw[dat_off:dat_off + n].hex().upper(),
        })
        if len(entries[-1]["old_hex"]) != n * 2:
            raise SystemExit("%s 读越界" % name)
    return entries


PS = r"""$ErrorActionPreference = 'Stop'
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
__PATCH_LINES__
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
"""

FRAME = """@echo off
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
if not exist "%MGOL_GAME%\\GundamOnline_CHINA.exe" (
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
set "PS1=%TEMP%\\mgol_camera_patch.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$l=Get-Content -LiteralPath '%~f0' -Encoding Default;$i=[Array]::IndexOf($l,'__MARK__');$p=$l[($i+1)..($l.Count-1)] -join [char]10;Set-Content -LiteralPath '%PS1%' -Value $p -Encoding Default"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
echo.
pause
exit /b
__MARK__
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="生成机库相机单文件补丁")
    ap.add_argument("--game", default=None, help="游戏根目录（含 GundamOnline_CHINA.exe）")
    ap.add_argument("--fpmf-dir", default=None, help="含 fpmf.py 的目录")
    ap.add_argument("--key-bin", default=None, help="备用 FPMF 密钥表（.bin）")
    ap.add_argument("--backup-root", default=str(Path.cwd() / "_msgo_camera_backup"),
                    help="patch_script_camera.py 的备份根目录")
    ap.add_argument("--out-dir", default=str(Path.cwd() / "camera-patch-dist"),
                    help="输出目录")
    args = ap.parse_args()

    game = resolve_game(args.game)
    backup = newest_backup(Path(args.backup_root).resolve())
    out_dir = Path(args.out_dir).resolve()
    fpmf = load_fpmf(args.fpmf_dir)
    entries = build_entries(game, backup, fpmf, args.key_bin)

    print("游戏目录 %s" % game)
    print("备份目录 %s" % backup)
    for e in entries:
        print("  %-42s dat 0x%08X  %2d 字节" % (e["name"], e["dat_offset"], e["size"]))

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "camera_patch.json").write_text(json.dumps({
        "note": "机库相机注视点等长改写；dat_offset 是 0000.dat 内的绝对偏移",
        "warning": "偏移与密文硬绑定于生成它的客户端 build；版本不同请勿复用",
        "backup_name": backup.name,
        "height": json.loads((backup / "meta.json").read_text(encoding="utf-8")).get("height"),
        "entries": entries,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = []
    for e in entries:
        lines.append('"%d|%d|%s|%s|%s"' % (e["dat_offset"], e["size"],
                                           e["old_hex"], e["new_hex"], e["name"]))
    ps = PS.replace("__PATCH_LINES__", "\n".join("  " + l for l in lines))
    assert ps.isascii(), "payload 段必须全 ASCII"
    assert "|" in lines[0]

    cmd = FRAME.replace("__MARK__", MARK) + ps
    data = (cmd.replace("\r\n", "\n").replace("\n", "\r\n")).encode("gbk")
    target = out_dir / "修复机库相机.cmd"
    target.write_bytes(data)
    print("\n写出 %s（%d 字节，GBK+CRLF）" % (target, len(data)))
    print("写出 %s" % (out_dir / "camera_patch.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
