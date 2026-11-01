#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""queue_patch.py —— 不附加调试器，直接找到"数据表下载队列"并清空它。

背景：
  客户端卡在"正在取得数据"：第 2 张表 msma/msma_weapon_set.csv 的加载器按表强类型
  校验，抛的异常被 0x544790 的 SEH 吞掉，队列不推进。CE/frida 一附加就被壳做掉
  （调试器检测），所以这里**不调试**，只用 OpenProcess + 内存读写。

原理（来自 0x544790 的反汇编）：
  ecx = 下载管理器；[ecx+8] = std::list 的哨兵节点；[哨兵] = 第一个队列节点。
  节点 +0x24 是一个 std::wstring（文件名），+0xc 是文件序号。
  把哨兵自环（next=prev=哨兵）就等于"队列里没有文件了"。

步骤：
  1. 在目标进程里搜文件名的 UTF-16LE / UTF-8 / GBK 字节，拿到字符串地址 S；
  2. 全内存搜"哪个 dword 等于 S" → 那个地址就是节点的 wstring 数据指针；
  3. 节点 = 该地址 - 0x24；顺着 node[0] 的 next 链走一圈，找到没有文件名的那个节点
     （哨兵）；
  4. --apply 时把哨兵 next/prev 写回自己。

用法：
    python tools/queue_patch.py --pid 1234 --dry-run      # 只看，不写
    python tools/queue_patch.py --pid 1234 --apply        # 真清空
    python tools/queue_patch.py --wait-log server/fake_auth.log --apply
        （等 fake_auth.log 里出现该文件名的 0xF86A 请求后再动手，时机最稳）

⚠️ 只写堆上的链表指针，不碰代码段，壳的自校验看不到。
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import struct
import sys
import time
from pathlib import Path

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READWRITE = 0x40
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD),
                ("Protect", wt.DWORD),
                ("Type", wt.DWORD)]


k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
k32.ReadProcessMemory.restype = wt.BOOL
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = wt.BOOL
k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


def log(msg):
    print(time.strftime("%H:%M:%S ") + msg, flush=True)


def open_proc(pid):
    for acc in (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION):
        h = k32.OpenProcess(acc, False, pid)
        if h:
            return h, acc
    return None, ctypes.get_last_error()


def regions(h, page_protect=None):
    """遍历 MEM_COMMIT 的可读写私有区（堆/数据）。"""
    addr = 0x10000
    mbi = MBI()
    while addr < 0x7FFF0000:
        got = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not got:
            addr += 0x10000
            continue
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        if size <= 0:
            break
        ok = (mbi.State == MEM_COMMIT
              and not (mbi.Protect & PAGE_GUARD)
              and mbi.Protect not in (PAGE_NOACCESS,)
              and mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE))
        if ok:
            yield base, size
        addr = base + size


def read(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)) and got.value:
        return buf.raw[:got.value]
    return None


def write_u32(h, addr, val):
    b = struct.pack("<I", val)
    got = ctypes.c_size_t(0)
    return bool(k32.WriteProcessMemory(h, ctypes.c_void_p(addr), b, 4, ctypes.byref(got)))


def scan_for(h, needles, chunk=2 << 20):
    """返回 [(地址, 命中的 needle)]"""
    hits = []
    total = 0
    for base, size in regions(h):
        off = 0
        while off < size:
            n = min(chunk, size - off)
            data = read(h, base + off, n)
            if data:
                total += len(data)
                for nb, tag in needles:
                    start = 0
                    while True:
                        i = data.find(nb, start)
                        if i < 0:
                            break
                        hits.append((base + off + i, tag))
                        start = i + 1
                        if len(hits) > 64:
                            return hits, total
            off += n
    return hits, total


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--name", default="msma/msma_weapon_set.csv")
    ap.add_argument("--apply", action="store_true", help="真写内存（默认只读检查）")
    ap.add_argument("--dry-run", action="store_true", help="（默认行为）只读检查")
    ap.add_argument("--wait", type=float, default=0.0, help="先等这么多秒再扫")
    a = ap.parse_args()

    h, acc = open_proc(a.pid)
    if not h:
        log("OpenProcess 失败 err=%s（权限不够：客户端是提权起的？）" % acc)
        return 2
    log("OpenProcess ok (access=0x%X)" % acc)

    if a.wait:
        log("等 %.0f 秒……" % a.wait)
        time.sleep(a.wait)

    needles = [(a.name.encode("utf-16le"), "utf16"),
               (a.name.encode("utf-8"), "utf8"),
               (a.name.encode("gbk", "replace"), "gbk")]
    hits, total = scan_for(h, needles)
    log("扫了 %.1f MB，命中 %d 处" % (total / 1048576.0, len(hits)))
    for addr, tag in hits[:20]:
        data = read(h, addr, 96)
        log("  hit @%08X (%s) %r" % (addr, tag, (data or b"")[:48]))

    if not hits:
        log("没找到文件名，队列可能还没建（要等客户端要到这张表）")
        return 1

    # 名字是内联定长数组（全内存没有任何指针指向它）→ 反推节点基址：
    #   节点 = 字符串地址 - delta（delta = 名字字段在节点里的偏移）
    #   判据：node+0/+4 都是合理堆指针，且沿 next 走一步后 (next+delta) 也是一条 .csv 名字
    def plausible(v):
        return 0x10000 < v < 0x7FFF0000

    def name_at(addr):
        raw = read(h, addr, 0x80)
        if not raw:
            return None
        z = raw.find(b"\x00")
        if z <= 3:
            return None
        s = raw[:z]
        return s if b".csv" in s or b".cfg" in s else None

    nodes = []
    for saddr, tag in hits:
        if tag != "utf16":
            continue
        for delta in range(0, 0x400 + 1, 4):
            node = saddr - delta
            raw = read(h, node, 0x18)
            if not raw:
                continue
            nxt, prv = struct.unpack_from("<II", raw, 0)
            if not (plausible(nxt) and plausible(prv)):
                continue
            n2 = name_at(nxt + delta)
            if n2:
                nodes.append((node, delta))
                log("  候选节点 %08X（delta=0x%X next=%08X prev=%08X 下一条=%s）"
                    % (node, delta, nxt, prv, n2.decode("ascii", "replace")))
                break
        if nodes:
            break

    if not nodes:
        log("没定位到节点（内联数组的偏移也没推出来）")
        return 1

    # 顺着 next 走一圈，找名字为空的那个（哨兵）
    for node, delta in nodes[:3]:
        seen = []
        cur = node
        sentinel = None
        for _ in range(300):
            raw = read(h, cur, 0x40)
            if not raw:
                break
            nxt = struct.unpack_from("<I", raw, 0)[0]
            prv = struct.unpack_from("<I", raw, 4)[0]
            idx = struct.unpack_from("<i", raw, 0xC)[0] if delta > 0x10 else -1
            nm = name_at(cur + delta)
            log("  walk %08X next=%08X prev=%08X idx=%d name=%s" %
                (cur, nxt, prv, idx,
                 nm.decode("ascii", "replace") if nm else "<空/无名字>"))
            seen.append(cur)
            if nm is None:
                sentinel = cur
                break
            if nxt in seen:
                break
            cur = nxt

        if not sentinel:
            log("!! 这一串没找到哨兵（可能走反了，或判据不对）")
            continue

        log("== 哨兵候选 %08X，队列长度 %d" % (sentinel, len(seen)))
        if a.apply:
            ok1 = write_u32(h, sentinel, sentinel)
            ok2 = write_u32(h, sentinel + 4, sentinel)
            log("写回自环: next=%s prev=%s" % (ok1, ok2))
            raw = read(h, sentinel, 8)
            if raw:
                log("复读: next=%08X prev=%08X" % struct.unpack("<II", raw))
        else:
            log("dry-run：没有写。加 --apply 才动手。")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
