#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""以管理员身份跑 `tools/start_local.cmd`（UAC 只点一次）。

为什么要这层外壳：
  - `run_hooked.py --fake all` 要伪造 OpenSCManagerW / CreateServiceW / CreateFileW
  - `clean_cps.py` 要删 CPS 服务键（否则 1073）
  - `hosts_guard.py` 要改 hosts
  - `auto_advance.py` 要 attach 到管理员权限的客户端进程
  全部需要管理员；而 PowerShell 侧不允许在工具里直接 Start-Process cmd.exe。

用法（普通终端）：
    python tools/start_local_admin.py

内部：非管理员 -> ShellExecuteExW(runas) 重启自己 -> 再 `cmd /c tools\\start_local.cmd`。
`start_local.cmd` 的 6 步编排完全不变，本脚本不复制它的逻辑。
"""
from __future__ import annotations

import ctypes
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CMD = ROOT / "tools" / "start_local.cmd"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", ctypes.c_ulong),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


def run_as_admin() -> int:
    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = 0x00000040              # SEE_MASK_NOCLOSEPROCESS
    sei.lpVerb = "runas"
    sei.lpFile = sys.executable
    sei.lpParameters = subprocess.list2cmdline(
        [str(Path(__file__).resolve()), "--inner"])
    sei.lpDirectory = str(ROOT)
    sei.nShow = 1
    print("[*] 需要管理员权限，正在提权……请在 UAC 窗口点【是】（只等 2 分钟）",
          flush=True)
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        err = ctypes.get_last_error()
        print(f"[X] 提权失败/被取消，错误码 {err}", flush=True)
        return 3
    print("[*] 已提交提权实例，本进程退出（真正的流程在新窗口里）", flush=True)
    return 0


def _clean_stale() -> None:
    """杀掉上一轮遗留的 fake_auth / auto_advance / fake_http / run_hooked / 客户端。

    为什么必须杀：`start_local.cmd` 发现 30000 已有人监听就会**跳过**启动 fake_auth，
    于是改了参数也不会生效（本项目的老坑）。
    """
    ps = (
        "Get-CimInstance Win32_Process -Filter "
        "\"Name='python.exe' or Name='pythonw.exe' or Name='GundamOnline_CHINA.exe'\" | "
        "Where-Object { $_.CommandLine -match "
        "'fake_auth|auto_advance|fake_http|run_hooked|xgg_hook' } | "
        "ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; "
        "\"killed \" + $_.ProcessId } catch { } }"
    )
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, timeout=60)
        out = (r.stdout or b"").decode("mbcs", "replace").strip()
        print("[*] 清理遗留进程: " + (out or "(无)"))
    except Exception as e:  # noqa: BLE001
        print(f"[!] 清理失败（继续）: {e}")
    # 客户端单独再杀一次，等它真的退出
    subprocess.run(["taskkill", "/F", "/IM", "GundamOnline_CHINA.exe"],
                   capture_output=True)
    time.sleep(2)


def main() -> int:
    if "--inner" not in sys.argv and not is_admin():
        return run_as_admin()

    if not CMD.exists():
        print(f"[X] 找不到 {CMD}", flush=True)
        return 2

    print(f"[*] 管理员 = {is_admin()}，启动 {CMD.name}", flush=True)
    _clean_stale()
    # CREATE_NEW_CONSOLE(0x10)：给 start_local.cmd 一个独立窗口，
    # 里面的 run_hooked.py 会前台跑 3000s，输出同时 tee 到
    # server/hook_runs/_pilot_run.log。
    subprocess.Popen(["cmd.exe", "/c", str(CMD)], cwd=str(ROOT),
                     creationflags=0x00000010)
    print("[*] 已拉起，本进程退出", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
