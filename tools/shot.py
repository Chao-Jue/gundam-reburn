#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""截取某个窗口（或全屏）并存成 PNG。纯 ctypes + zlib，不依赖 PIL。

用法：
    python tools/shot.py --pid 1234                 # 截该进程主窗口
    python tools/shot.py --title "Mobile Suit"      # 按标题子串找窗口
    python tools/shot.py --out D:\\x.png            # 指定输出
    python tools/shot.py --full                     # 截整个虚拟屏幕
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import struct
import zlib

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32

EnumWindowsProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

SRCCOPY = 0x00CC0020
DIB_RGB_COLORS = 0


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wt.DWORD), ("biWidth", wt.LONG), ("biHeight", wt.LONG),
                ("biPlanes", wt.WORD), ("biBitCount", wt.WORD),
                ("biCompression", wt.DWORD), ("biSizeImage", wt.DWORD),
                ("biXPelsPerMeter", wt.LONG), ("biYPelsPerMeter", wt.LONG),
                ("biClrUsed", wt.DWORD), ("biClrImportant", wt.DWORD)]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wt.DWORD * 3)]


def window_text(hwnd: int) -> str:
    n = user32.GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(n + 1)
    user32.GetWindowTextW(hwnd, buf, n + 1)
    return buf.value


def find_window(pid: int | None, title: str | None) -> int:
    hits: list[tuple[int, str]] = []

    def cb(hwnd, _):
        if not user32.IsWindowVisible(hwnd):
            return True
        t = window_text(hwnd)
        if title and title.lower() in t.lower():
            hits.append((hwnd, t))
            return True
        if pid is not None:
            p = wt.DWORD(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
            if p.value == pid and t:
                hits.append((hwnd, t))
        return True

    user32.EnumWindows(EnumWindowsProc(cb), 0)
    if not hits:
        return 0
    return hits[0][0]


def write_png(path: str, width: int, height: int, bgra: bytes) -> None:
    """bgra 是自下而上的 BGRA 数据。"""
    raw = bytearray()
    stride = width * 4
    for y in range(height - 1, -1, -1):
        raw.append(0)
        row = bgra[y * stride:(y + 1) * stride]
        raw.extend(row[y2] for y2 in range(stride))
    # 转 RGB（raw 每行开头有一个 filter 字节）
    rgb = bytearray()
    for y in range(height):
        src_off = y * (stride + 1) + 1
        rgb.append(0)
        line = raw[src_off:src_off + stride]
        for x in range(width):
            b, g, r = line[x * 4], line[x * 4 + 1], line[x * 4 + 2]
            rgb += bytes((r, g, b))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
           + chunk(b"IDAT", zlib.compress(bytes(rgb), 6)) + chunk(b"IEND", b""))
    with open(path, "wb") as fh:
        fh.write(png)


def capture(hwnd: int, x: int, y: int, w: int, h: int) -> bytes:
    hdc = user32.GetDC(hwnd) if hwnd else user32.GetDC(0)
    mem = gdi32.CreateCompatibleDC(hdc)
    bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
    old = gdi32.SelectObject(mem, bmp)
    gdi32.BitBlt(mem, 0, 0, w, h, hdc, x, y, SRCCOPY)
    bi = BITMAPINFO()
    bi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bi.bmiHeader.biWidth = w
    bi.bmiHeader.biHeight = h
    bi.bmiHeader.biPlanes = 1
    bi.bmiHeader.biBitCount = 32
    bi.bmiHeader.biCompression = 0
    buf = ctypes.create_string_buffer(w * h * 4)
    gdi32.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(bi), DIB_RGB_COLORS)
    gdi32.SelectObject(mem, old)
    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(mem)
    user32.ReleaseDC(hwnd, hdc)
    return buf.raw


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--title", default=None)
    ap.add_argument("--out", default=r"D:\project\gundam-reburn\server\hook_runs\_shot.png")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--crop", default=None, metavar="X,Y,W,H")
    ap.add_argument("--zoom", type=int, default=1, help="最近邻放大倍数")
    args = ap.parse_args()

    if args.full:
        hwnd = 0
        w = user32.GetSystemMetrics(78)   # SM_CXVIRTUALSCREEN
        h = user32.GetSystemMetrics(79)
        x = user32.GetSystemMetrics(76)
        y = user32.GetSystemMetrics(77)
        print(f"虚拟屏幕 {w}x{h} @({x},{y})")
    else:
        hwnd = find_window(args.pid, args.title)
        if not hwnd:
            print("[X] 找不到窗口")
            return 1
        r = wt.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(r))
        x, y, w, h = r.left, r.top, r.right - r.left, r.bottom - r.top
        print(f"窗口 hwnd=0x{hwnd:x} {window_text(hwnd)!r} {w}x{h} @({x},{y})")
        if w <= 0 or h <= 0:
            print("[X] 窗口尺寸为 0（最小化？）")
            return 1

    data = capture(hwnd, x, y, w, h)
    if args.crop:
        cx, cy, cw, ch = (int(v) for v in args.crop.split(","))
        # data 来自 GetDIBits，是自下而上（bottom-up）的；crop 用 top-down 坐标，
        # 需要换算回 data 的行号：d = h - 1 - r，且保持输出仍是 bottom-up。
        stride = w * 4
        d0 = h - cy - ch
        if d0 < 0:
            print("[!] crop 超出高度")
            d0 = 0
        out = bytearray()
        for row in range(ch):
            off = (d0 + row) * stride + cx * 4
            out += data[off:off + cw * 4]
        data, w, h = bytes(out), cw, ch
    if args.zoom > 1:
        z = args.zoom
        stride = w * 4
        out = bytearray()
        for row in range(h):
            line = data[row * stride:(row + 1) * stride]
            big = bytearray()
            for px in range(w):
                big += line[px * 4:px * 4 + 4] * z
            for _ in range(z):
                out += big
        data, w, h = bytes(out), w * z, h * z
    write_png(args.out, w, h, data)
    import os
    print(f"[+] 已保存 {args.out} ({os.path.getsize(args.out)} B)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
