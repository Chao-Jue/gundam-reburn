#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""把窗口画面降采样成 ASCII 亮度图，用于定位深色 UI 面板。

用法：
    python tools/cropfind.py --pid 1234
    python tools/cropfind.py --pid 1234 --cols 80 --rows 45 --dark 70
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import shot as S  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--cols", type=int, default=80)
    ap.add_argument("--rows", type=int, default=45)
    ap.add_argument("--dark", type=int, default=80, help="判定为面板的亮度阈值")
    args = ap.parse_args()

    hwnd = S.find_window(args.pid, None)
    if not hwnd:
        return 1
    r = wt.RECT()
    ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(r))
    x, y, w, h = r.left, r.top, r.right - r.left, r.bottom - r.top
    data = S.capture(hwnd, x, y, w, h)
    stride = w * 4

    cw, ch = w // args.cols, h // args.rows
    grid: list[list[int]] = []
    for gy in range(args.rows):
        row = []
        for gx in range(args.cols):
            tot = 0
            n = 0
            for yy in range(gy * ch, (gy + 1) * ch, 2):
                base = yy * stride
                for xx in range(gx * cw, (gx + 1) * cw, 2):
                    o = base + xx * 4
                    tot += data[o] + data[o + 1] + data[o + 2]
                    n += 3
            row.append(tot // max(1, n))
        grid.append(row)

    print(f"窗口 {w}x{h} -> 格子 {cw}x{ch}，每字符一格；数字=亮度/10")
    print("     " + "".join(str((gx // 10) % 10) for gx in range(args.cols)))
    for gy, row in enumerate(grid):
        line = "".join("#" if v < args.dark else ("." if v < 110 else " ") for v in row)
        print(f"{gy:3d}  {line}   y={gy * ch:4d}")

    # 找出最大的连通深色块（逐行给出深色区间）
    print("\n每行深色区间（x 像素）:")
    for gy, row in enumerate(grid):
        xs = [gx for gx, v in enumerate(row) if v < args.dark]
        if len(xs) >= 4:
            print(f"  y={gy * ch:4d}-{gy * ch + ch:4d}  x={xs[0] * cw}..{xs[-1] * cw + cw}"
                  f"  宽={xs[-1] * cw + cw - xs[0] * cw}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
