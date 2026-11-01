#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按 PID / 窗口类名截取**指定窗口**内容（不依赖前台）。

优先 PrintWindow(PW_RENDERFULLCONTENT)，失败再退化为「置顶 -> 屏幕 BitBlt」。
纯 ctypes + GDI，不依赖 PowerShell（本机安全策略会拦 Add-Type）。

用法：
    python tools/win_shot.py --pid 1234 --out server/a.png
    python tools/win_shot.py --class "Mobile Suit Gundam Online" --out b.png
    python tools/win_shot.py --pid 1234 --focus --out c.png   # 允许抢前台
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import pathlib
import struct
import sys
import time
import zlib

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32

PW_RENDERFULLCONTENT = 0x00000002
SRCCOPY = 0x00CC0020
DIB_RGB_COLORS = 0


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wt.DWORD), ("biWidth", wt.LONG), ("biHeight", wt.LONG),
        ("biPlanes", wt.WORD), ("biBitCount", wt.WORD),
        ("biCompression", wt.DWORD), ("biSizeImage", wt.DWORD),
        ("biXPelsPerMeter", wt.LONG), ("biYPelsPerMeter", wt.LONG),
        ("biClrUsed", wt.DWORD), ("biClrImportant", wt.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wt.DWORD * 3)]


def find_window(pid: int | None, cls: str | None) -> tuple[int, tuple[int, int, int, int]]:
    found: list[tuple[int, tuple[int, int, int, int]]] = []

    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def cb(hwnd, _lp):
        if not user32.IsWindowVisible(hwnd):
            return True
        buf = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, buf, 256)
        cname = buf.value
        if cls and cls.lower() not in cname.lower():
            return True
        if pid:
            wpid = wt.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
            if wpid.value != pid:
                return True
        r = wt.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(r))
        w, h = r.right - r.left, r.bottom - r.top
        if w < 64 or h < 64:
            return True
        found.append((hwnd, (r.left, r.top, w, h)))
        return True

    user32.EnumWindows(cb, 0)
    if not found:
        raise SystemExit("[X] 找不到窗口")
    found.sort(key=lambda x: -(x[1][2] * x[1][3]))
    return found[0]


def grab(hwnd: int, rect: tuple[int, int, int, int], full_content: bool) -> tuple[int, int, bytes]:
    x, y, w, h = rect
    hdc_screen = user32.GetDC(0)
    hdc_mem = gdi32.CreateCompatibleDC(hdc_screen)
    hbm = gdi32.CreateCompatibleBitmap(hdc_screen, w, h)
    gdi32.SelectObject(hdc_mem, hbm)
    ok = 0
    if full_content:
        ok = user32.PrintWindow(hwnd, hdc_mem, PW_RENDERFULLCONTENT)
    if not ok:
        ok = gdi32.BitBlt(hdc_mem, 0, 0, w, h, hdc_screen, x, y, SRCCOPY)

    bi = BITMAPINFO()
    bi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bi.bmiHeader.biWidth = w
    bi.bmiHeader.biHeight = -h            # 负数 = 自上而下
    bi.bmiHeader.biPlanes = 1
    bi.bmiHeader.biBitCount = 32
    bi.bmiHeader.biCompression = 0
    buf = ctypes.create_string_buffer(w * h * 4)
    gdi32.GetDIBits(hdc_mem, hbm, 0, h, buf, ctypes.byref(bi), DIB_RGB_COLORS)

    gdi32.DeleteObject(hbm)
    gdi32.DeleteDC(hdc_mem)
    user32.ReleaseDC(0, hdc_screen)
    return w, h, buf.raw, ok


def save_png(path: pathlib.Path, w: int, h: int, bgra: bytes) -> None:
    rows = []
    for yy in range(h):
        off = yy * w * 4
        row = bgra[off:off + w * 4]
        # BGRA -> RGB
        rgb = bytearray(w * 3)
        rgb[0::3] = row[2::4]
        rgb[1::3] = row[1::4]
        rgb[2::3] = row[0::4]
        rows.append(b"\x00" + bytes(rgb))
    raw = b"".join(rows)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw, 6))
           + chunk(b"IEND", b""))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(png)


def force_foreground(hwnd: int) -> None:
    """抢前台。SetForegroundWindow 有前台锁，用 AttachThreadInput 绕过。"""
    user32.ShowWindow(hwnd, 9)                     # SW_RESTORE
    user32.SetWindowPos(hwnd, -1, 0, 0, 0, 0,       # HWND_TOPMOST
                        0x0001 | 0x0002)           # SWP_NOSIZE | SWP_NOMOVE
    fg = user32.GetForegroundWindow()
    tid_fg = user32.GetWindowThreadProcessId(fg, None)
    tid_me = ctypes.windll.kernel32.GetCurrentThreadId()
    tid_tg = user32.GetWindowThreadProcessId(hwnd, None)
    attached_fg = user32.AttachThreadInput(tid_me, tid_fg, True)
    attached_tg = user32.AttachThreadInput(tid_me, tid_tg, True)
    try:
        user32.BringWindowToTop(hwnd)
        user32.SetForegroundWindow(hwnd)
        user32.SetFocus(hwnd)
    finally:
        if attached_tg:
            user32.AttachThreadInput(tid_me, tid_tg, False)
        if attached_fg:
            user32.AttachThreadInput(tid_me, tid_fg, False)
    # 退回非置顶，避免之后一直盖在别的窗口上
    user32.SetWindowPos(hwnd, -2, 0, 0, 0, 0,       # HWND_NOTOPMOST
                        0x0001 | 0x0002)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--class", dest="cls", default=None)
    ap.add_argument("--out", default=r"D:\project\gundam-reburn\server\hook_runs\_win.png")
    ap.add_argument("--focus", action="store_true", help="先抢前台再截（PrintWindow 失败时用）")
    a = ap.parse_args()

    hwnd, rect = find_window(a.pid, a.cls)
    print(f"[窗口] hwnd=0x{hwnd:08x} rect={rect}")
    if a.focus:
        force_foreground(hwnd)
        time.sleep(0.6)
        w, h, bgra, ok = grab(hwnd, rect, False)
    else:
        w, h, bgra, ok = grab(hwnd, rect, True)
    print(f"[抓图] {w}x{h} ok={ok}")
    out = pathlib.Path(a.out)
    save_png(out, w, h, bgra)
    print(f"[+] 已保存 {out} ({out.stat().st_size:,} B)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
