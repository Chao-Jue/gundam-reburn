#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""用 UAC 提权跑一条命令，并把输出落到文件。

背景：本项目的很多步骤需要管理员（OpenSCManagerW / CreateServiceW / frida 注入
提权进程 / bcdedit / sc）。而 agent 自己的 shell 不一定是提权的。
这个工具把「提权 + 收集输出」做成一步，免得反复麻烦你手动开管理员终端。

用法：
    python tools/elevate_run.py --out server/hook_runs/_run14.out -- <命令...>

例：
    python tools/elevate_run.py --out server/hook_runs/_run14.out -- \
        "C:/Users/86186/.workbuddy/binaries/python/envs/default/Scripts/python.exe" \
        tools/run_hooked.py --no-elevate --seconds 60 --fresh

要点：
  - 命令在项目根目录下、由提权的 cmd.exe 执行；
  - stdout/stderr 合并写进 --out 指定的文件（相对路径按项目根解析）；
  - 会弹一次 UAC，请点“是”。1223 = 你点了“否”。
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class _SEI(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wt.HWND),
        ("lpVerb", wt.LPCWSTR), ("lpFile", wt.LPCWSTR), ("lpParameters", wt.LPCWSTR),
        ("lpDirectory", wt.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wt.HINSTANCE),
        ("lpIDList", ctypes.c_void_p), ("lpClass", wt.LPCWSTR), ("hkeyClass", wt.HKEY),
        ("dwHotKey", wt.DWORD), ("hIcon", wt.HANDLE), ("hProcess", wt.HANDLE),
    ]


def is_admin() -> bool:
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def run_elevated(command: str, workdir: Path) -> int:
    """提权跑 `cmd /c command`，等待结束，返回退出码。"""
    sei = _SEI()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = 0x00000040 | 0x00000100          # NOCLOSEPROCESS | NOASYNC
    sei.lpVerb = "runas"
    sei.lpFile = "cmd.exe"
    sei.lpParameters = "/c " + command
    sei.lpDirectory = str(workdir)
    sei.nShow = 0                                 # 不闪控制台窗口（SW_HIDE）
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        err = ctypes.get_last_error()
        raise OSError(f"提权失败，错误码 {err}" + ("（你点了“否”）" if err == 1223 else ""))
    ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, 600_000)
    code = wt.DWORD()
    ctypes.windll.kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(code))
    ctypes.windll.kernel32.CloseHandle(sei.hProcess)
    return int(code.value)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=None, help="把输出写到这个文件")
    ap.add_argument("--no-elevate", action="store_true", help="不检查权限，直接跑")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="要执行的命令")
    args = ap.parse_args()

    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        ap.error("缺少要执行的命令")

    # 带空格/斜杠的参数逐个人工加引号，交给 cmd /c
    parts = []
    for a in cmd:
        a = a.replace('"', '\\"')
        parts.append(f'"{a}"' if (" " in a or "/" in a or "\\" in a) else a)
    command = " ".join(parts)

    out = None
    if args.out:
        out = Path(args.out)
        if not out.is_absolute():
            out = ROOT / out
        out.parent.mkdir(parents=True, exist_ok=True)
        command = f"{command} > \"{out}\" 2>&1"
        print(f"[*] 输出 -> {out}")
    print(f"[*] 提权执行: {command}")

    if args.no_elevate or is_admin():
        proc = subprocess.run(command, shell=True, cwd=str(ROOT))
        return proc.returncode

    try:
        code = run_elevated(command, ROOT)
    except OSError as e:
        print(f"[X] {e}")
        return 3
    print(f"[*] 提权子进程退出码 = {code}")
    if out is not None:
        try:
            text = out.read_text(encoding="utf-8", errors="replace")
            print("[*] ---- 子进程输出 ----")
            print(text)
        except Exception as e:  # noqa: BLE001
            print(f"[!] 读输出失败: {e}")
    return code


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass
    raise SystemExit(main())
