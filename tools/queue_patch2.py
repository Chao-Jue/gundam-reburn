#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""queue_patch2.py —— 找下载队列节点（多假设版），先 dump 结构再决定是否清空。

相比 queue_patch.py 的变化：
  · 同时考虑 UTF-8 / UTF-16 命中；
  · 先把命中点 **前面 0x60 字节** dump 出来（节点头/链接就在那里）；
  · 节点判定放宽：node+0/+4 是两个合理堆指针即可，再用"同偏移上有 .csv 名字"加分；
  · 找到后顺着 next 走，名字字段为空的那个就是 std::list 的哨兵；
  · 默认只读，--apply 才写。

用法：
    python tools/queue_patch2.py --pid 39056            # 只读 + dump
    python tools/queue_patch2.py --pid 39056 --apply    # 定位后清空队列
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import struct
import sys
import time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
VM_R, VM_W, VM_OP, QUERY = 0x0010, 0x0020, 0x0008, 0x0400
MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS = 0x1000, 0x100, 0x01
RW_MASK = 0x04 | 0x08 | 0x40          # READWRITE | WRITECOPY | EXECUTE_READWRITE


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]


k32.OpenProcess.restype = wt.HANDLE
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.ReadProcessMemory.restype = wt.BOOL
k32.WriteProcessMemory.restype = wt.BOOL


def log(m):
    print(time.strftime("%H:%M:%S ") + m, flush=True)


def read(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(addr), buf, n, ctypes.byref(got)) and got.value:
        return buf.raw[:got.value]
    return None


def write_u32(h, addr, val):
    b = struct.pack("<I", val)
    got = ctypes.c_size_t(0)
    return bool(k32.WriteProcessMemory(wt.HANDLE(h), ctypes.c_void_p(addr), b, 4, ctypes.byref(got)))


def regions(h):
    addr, mbi = 0x10000, MBI()
    while addr < 0x7FFF0000:
        if not k32.VirtualQueryEx(wt.HANDLE(h), ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            addr += 0x10000
            continue
        base, size = mbi.BaseAddress or 0, mbi.RegionSize or 0
        if size <= 0:
            break
        if (mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD)
                and mbi.Protect != PAGE_NOACCESS and (mbi.Protect & RW_MASK)):
            yield base, size
        addr = base + size


def hexdump(addr, data):
    for p in range(0, len(data), 16):
        seg = data[p:p + 16]
        asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in seg)
        log("  %08X  %-47s  %s" % (addr + p, ' '.join('%02x' % c for c in seg), asc))


def plausible(v):
    return 0x10000 < v < 0x7FFF0000


def name_at(h, addr, limit=0x60):
    raw = read(h, addr, limit)
    if not raw:
        return None
    z = raw.find(b"\x00")
    if 0 < z and (b".csv" in raw[:z] or b".cfg" in raw[:z]):
        return raw[:z]
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--name", default="msma/msma_weapon_set.csv")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--dump", type=int, default=4, help="dump 前 N 个命中点的前置字节")
    a = ap.parse_args()

    h = k32.OpenProcess(VM_R | VM_W | VM_OP | QUERY, False, a.pid)
    if not h:
        log("OpenProcess 失败 err=%d" % ctypes.get_last_error())
        return 2
    log("handle ok")

    needles = [(a.name.encode("utf-16le"), "w"), (a.name.encode("utf-8"), "a")]
    hits, total = [], 0
    for base, size in regions(h):
        off = 0
        while off < size:
            n = min(2 << 20, size - off)
            d = read(h, base + off, n)
            if d:
                total += len(d)
                for nb, tag in needles:
                    i = 0
                    while True:
                        j = d.find(nb, i)
                        if j < 0:
                            break
                        hits.append((base + off + j, tag))
                        i = j + 1
            off += n
    log("扫 %.1f MB 命中 %d 处" % (total / 1048576.0, len(hits)))
    if not hits:
        log("没找到名字")
        return 1

    for addr, tag in hits[:a.dump]:
        log("== hit %08X (%s) 前置 0x60 ==" % (addr, tag))
        pre = read(h, max(0, addr - 0x60), 0x60)
        if pre:
            hexdump(addr - 0x60, pre)

    # 多假设：字符串前面 0x400 内某个偏移上是节点头（两个合法堆指针）
    cands = []
    for addr, tag in hits:
        for delta in range(0x00, 0x401, 4):
            node = addr - delta
            raw = read(h, node, 8)
            if not raw:
                continue
            nxt, prv = struct.unpack("<II", raw)
            if not (plausible(nxt) and plausible(prv)):
                continue
            if nxt == node or prv == node:
                continue
            # 加分项：沿 next 走一步，同一 delta 上还是 csv 名字
            ok = 1 if name_at(h, nxt + delta) else 0
            cands.append((ok, node, delta, nxt, prv))
            if ok:
                break

    cands.sort(reverse=True)
    log("候选 %d 个（按可信度排序，最多列 8 个）" % len(cands))
    for ok, node, delta, nxt, prv in cands[:8]:
        log("  node=%08X delta=%02X next=%08X prev=%08X %s"
            % (node, delta, nxt, prv, "★名字对上" if ok else ""))
        raw = read(h, node, 0x60)
        if raw:
            hexdump(node, raw)

    if not cands:
        log("没有候选：字符串周围没有像链表节点的结构")
        return 1

    starred = [c for c in cands if c[0]]
    log("★（下一条同偏移还是 .csv 名字）候选 %d 个" % len(starred))
    walk_list = starred[:3] if starred else cands[:1]

    # 用最可信的候选走链表
    for ok, node, delta, nxt, prv in walk_list:
        log("-- 试走 node=%08X delta=%02X" % (node, delta))
        cur, seen, sentinel = node, [], None
        for _ in range(200):
            raw = read(h, cur, 8)
            if not raw:
                break
            nx, pv = struct.unpack("<II", raw)
            nm = name_at(h, cur + delta)
            log("   %08X next=%08X prev=%08X name=%s" %
                (cur, nx, pv, nm.decode('ascii', 'replace') if nm else '<空>'))
            seen.append(cur)
            if nm is None:
                sentinel = cur
                break
            if nx in seen:
                break
            cur = nx

        if not sentinel:
            continue
        log("=> 哨兵 %08X（队列 %d 项）" % (sentinel, len(seen) - 1))
        if not a.apply:
            log("dry-run，未写。加 --apply 才清空。")
            return 0
        ok1 = write_u32(h, sentinel, sentinel)
        ok2 = write_u32(h, sentinel + 4, sentinel)
        log("写自环 next=%s prev=%s" % (ok1, ok2))
        raw = read(h, sentinel, 8)
        if raw:
            log("复读 next=%08X prev=%08X" % struct.unpack("<II", raw))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
