#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""向屏幕绝对坐标发送一次鼠标左键点击（SendInput，对 DirectInput 游戏同样有效）。

用法：
    python tools/click.py 888 795            # 单击
    python tools/click.py 888 795 --wait 0.2 # 按下与抬起间隔
    python tools/click.py 888 795 --double
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import sys
import time

user32 = ctypes.windll.user32

MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_ABSOLUTE = 0x8000
SM_CXSCREEN, SM_CYSCREEN = 0, 1


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wt.LONG), ("dy", wt.LONG), ("mouseData", wt.DWORD),
                ("dwFlags", wt.DWORD), ("time", wt.DWORD),
                ("dwExtraInfo", ctypes.POINTER(wt.ULONG))]


class INPUT(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("mi", MOUSEINPUT)]
    _anonymous_ = ("_u",)
    _fields_ = [("type", wt.DWORD), ("_u", _U)]


def send(flags: int, x: int = 0, y: int = 0) -> None:
    sw, sh = user32.GetSystemMetrics(SM_CXSCREEN), user32.GetSystemMetrics(SM_CYSCREEN)
    inp = INPUT()
    inp.type = 0                      # INPUT_MOUSE
    inp.mi.dx = int(x * 65535 / max(sw - 1, 1))
    inp.mi.dy = int(y * 65535 / max(sh - 1, 1))
    inp.mi.dwFlags = flags
    user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("x", type=int)
    ap.add_argument("y", type=int)
    ap.add_argument("--wait", type=float, default=0.12)
    ap.add_argument("--double", action="store_true")
    a = ap.parse_args()

    sw, sh = user32.GetSystemMetrics(SM_CXSCREEN), user32.GetSystemMetrics(SM_CYSCREEN)
    print(f"[屏幕] {sw}x{sh}  目标=({a.x},{a.y})")
    times = 2 if a.double else 1
    for i in range(times):
        send(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, a.x, a.y)
        time.sleep(0.05)
        send(MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_ABSOLUTE, a.x, a.y)
        time.sleep(a.wait)
        send(MOUSEEVENTF_LEFTUP | MOUSEEVENTF_ABSOLUTE, a.x, a.y)
        print(f"[+] 第 {i+1} 次点击已发送")
        time.sleep(0.25)
    return 0


if __name__ == "__main__":
    sys.exit(main())
