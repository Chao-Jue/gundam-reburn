#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""枚举顶层窗口（含对话框），用于判断客户端是不是被模态框挡住了。

用法：
    python tools/winlist.py                 # 全部可见顶层窗口
    python tools/winlist.py --pid 36924     # 只看某个进程
    python tools/winlist.py --all           # 含隐藏窗口
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt

user32 = ctypes.windll.user32

EnumWindowsProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def text(hwnd: int) -> str:
    n = user32.GetWindowTextLengthW(hwnd)
    if n <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(n + 1)
    user32.GetWindowTextW(hwnd, buf, n + 1)
    return buf.value


def cls(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, buf, 256)
    return buf.value


def owner_pid(hwnd: int) -> int:
    pid = wt.DWORD(0)
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def rect(hwnd: int) -> tuple[int, int, int, int]:
    r = wt.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(r))
    return r.left, r.top, r.right, r.bottom


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--all", action="store_true", help="含不可见窗口")
    args = ap.parse_args()

    rows: list[str] = []

    def cb(hwnd, _):
        pid = owner_pid(hwnd)
        if args.pid is not None and pid != args.pid:
            return True
        vis = bool(user32.IsWindowVisible(hwnd))
        if not vis and not args.all:
            return True
        l, t, r, b = rect(hwnd)
        rows.append(f"  hwnd=0x{hwnd:08x} pid={pid:<6} vis={int(vis)} "
                    f"cls={cls(hwnd)!r:<28} title={text(hwnd)!r} "
                    f"rect=({l},{t},{r},{b}) {r - l}x{b - t}")
        return True

    user32.EnumWindows(EnumWindowsProc(cb), 0)
    print(f"共 {len(rows)} 个窗口")
    for line in rows:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
