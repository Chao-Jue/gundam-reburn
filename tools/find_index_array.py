#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""find_index_array.py —— 用"文件序号等差序列"定位 74 项下载表。

依据（0x544790 反汇编）：队列节点 +0xc 是文件序号，节点按 0x?? 步长排列。
74 项连在一起 → 内存里必然有一段 `1,2,3,...,74` 的等差序列（步长 = 节点大小）。

做法：把所有可读写内存按 4 字节解释成数组，对每个候选步长 S 检查
      arr[i+S/4] == arr[i]+1 的最长连续段，段长 ≥ 10 就报出来。

只读，不写任何东西。

用法：python tools/find_index_array.py --pid 39056
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import struct
import time

import numpy as np

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]


def log(m):
    print(time.strftime("%H:%M:%S ") + m, flush=True)


def read(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(addr), buf, n, ctypes.byref(got)) and got.value:
        return buf.raw[:got.value]
    return None


def regions(h):
    a, mbi = 0x10000, MBI()
    while a < 0x7FFF0000:
        if not k32.VirtualQueryEx(wt.HANDLE(h), ctypes.c_void_p(a), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            a += 0x10000
            continue
        base, size = mbi.BaseAddress or 0, mbi.RegionSize or 0
        if size <= 0:
            break
        if (mbi.State == 0x1000 and not (mbi.Protect & 0x100)
                and (mbi.Protect & (0x04 | 0x08 | 0x40)) and size >= 0x1000):
            yield base, size
        a = base + size


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--min-run", type=int, default=10)
    ap.add_argument("--apply", action="store_true", help="命中后把哨兵改成自环（清空队列）")
    a = ap.parse_args()

    h = k32.OpenProcess(0x0010 | 0x0400, False, a.pid)
    if not h:
        log("OpenProcess 失败 err=%d" % ctypes.get_last_error())
        return 2

    strides = [0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C,
               0x40, 0x44, 0x48, 0x4C, 0x50, 0x58, 0x60, 0x68, 0x70, 0x80]
    best = []
    total = 0
    for base, size in regions(h):
        data = read(h, base, size)
        if not data:
            continue
        total += len(data)
        n = len(data) // 4
        if n < 64:
            continue
        arr = np.frombuffer(data[:n * 4], dtype="<u4")
        for S in strides:
            d = S // 4
            if d >= n:
                continue
            x = arr[:-d].astype(np.int64)
            y = arr[d:].astype(np.int64)
            m = (y == x + 1) & (x >= 0) & (x <= 200)
            if not m.any():
                continue
            idx = np.flatnonzero(m)
            # 找最长连续命中（在 m 的意义上连续：i, i+d, i+2d ... 已经是按步长取样，所以这里看 idx 的连续性）
            run_start = idx[0]
            run_len = 1
            bs, bl = idx[0], 1
            for k in range(1, len(idx)):
                if idx[k] == idx[k - 1] + d:
                    bl += 1
                    if bl > run_len:
                        run_len, run_start = bl, bs
                else:
                    bs, bl = idx[k], 1
                if bl > run_len:
                    run_len, run_start = bl, bs
            if run_len >= a.min_run:
                best.append((run_len, S, base + run_start * 4, int(arr[run_start])))
    log("扫了 %.1f MB" % (total / 1048576.0))
    best.sort(reverse=True)
    log("候选（按长度，只认 first<=2 且 run>=50）:")
    strict = [b for b in best if b[3] <= 2 and b[0] >= 50]
    for run_len, S, addr, first in strict[:6]:
        log("  run=%-3d stride=0x%-3X start=%08X first=%d" % (run_len, S, addr, first))
    if not strict:
        log("  没有满足条件的序列（first<=2 且 run>=50）")
        for run_len, S, addr, first in best[:6]:
            log("  噪声样本 run=%-3d stride=0x%-3X first=%d" % (run_len, S, first))
        return 1

    for run_len, S, addr, first in strict[:3]:
        node0 = int(addr) - 0xC                      # +0xc = 文件序号
        raw = read(h, node0, 8)
        if not raw:
            continue
        nxt, prv = struct.unpack("<II", raw)
        log("  验证 node0=%08X next=%08X prev=%08X" % (node0, nxt, prv))
        if not (0x10000 < prv < 0x7FFF0000):
            continue
        back = read(h, prv, 8)
        if not back:
            continue
        bnext = struct.unpack("<I", back[:4])[0]
        log("  哨兵候选 %08X -> next=%08X (%s)"
            % (prv, bnext, "回指首节点 ✓" if bnext == node0 else "不匹配 ✗"))
        if bnext != node0:
            continue
        if not a.apply:
            log("  dry-run，未写")
            return 0
        b = struct.pack("<II", prv, prv)
        w = ctypes.c_size_t(0)
        ok = k32.WriteProcessMemory(wt.HANDLE(h), ctypes.c_void_p(prv), b, 8, ctypes.byref(w))
        log("  写哨兵自环 -> %s" % bool(ok))
        chk = read(h, prv, 8)
        if chk:
            log("  复读 next=%08X prev=%08X" % struct.unpack("<II", chk))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
