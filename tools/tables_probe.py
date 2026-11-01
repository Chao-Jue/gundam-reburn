#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""只读探针：把「表下载器」对象的真实状态读出来（不写任何字节）。

为什么需要它
------------
静态已经确认下载器是挂在会话对象 `DAT_0117d380` 的 `+0x580` 上的 20 字节对象：
    +0x00 vtable(0xcb9edc)
    +0x08 std::map<wstring, ...> 的 _Myhead 哨兵
    +0x0C 发送闸门 / 完成判据（==0 就算"下载完成"，tick 会析构并置空 [X+0x580]）
    +0x10 标志位，bit0 = "有下一张待发"
但静态找不到 +0x0C 的写入点（构造函数写 0，没有别的写入）。
所以只能运行期读一次：`+0x0C` 到底是 0 还是非 0，决定了卡点在哪一侧。

用法（必须提权，否则读不到别的进程）
    python tools/tables_probe.py              # 自动找客户端
    python tools/tables_probe.py --pid 1234
"""
from __future__ import annotations

import argparse
import ctypes
import subprocess
import sys
from ctypes import wintypes as w

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

BASE_EXPECT = 0x400000
SESSION_GLOBAL = 0x117D380      # DAT_0117d380：0x7A60 字节的会话对象指针
TABLES_OFF = 0x580              # [session + 0x580] = 表下载器

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_OPERATION = 0x0008

PROCESS_VM_WRITE = 0x0020
k32.WriteProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = w.BOOL
k32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
k32.OpenProcess.restype = w.HANDLE
k32.ReadProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = w.BOOL
k32.CloseHandle.argtypes = [w.HANDLE]
k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
k32.GetModuleHandleW.restype = w.HMODULE


def find_pid(exe='GundamOnline_CHINA.exe') -> int:
    out = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {exe}', '/FO', 'CSV', '/NH'],
                         capture_output=True)
    for line in out.stdout.decode('mbcs', 'replace').splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[0].lower() == exe.lower():
            try:
                return int(parts[1])
            except ValueError:
                pass
    return 0


class Reader:
    def __init__(self, h):
        self.h = h
        self.bad = 0

    def raw(self, addr: int, n: int) -> bytes | None:
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(self.h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got))
        if not ok or got.value != n:
            self.bad += 1
            return None
        return buf.raw

    def u32(self, addr: int) -> int | None:
        b = self.raw(addr, 4)
        return None if b is None else int.from_bytes(b, 'little')

    def wstr(self, addr: int, maxchars: int = 200) -> str | None:
        """std::wstring 在 addr：buf(16B 内联) / size@+0x10 / cap@+0x14（字节级：+0x14/+0x24/+0x28）。"""
        size = self.u32(addr + 0x10)     # +0x24 - 0x14
        cap = self.u32(addr + 0x14)      # +0x28 - 0x14
        if size is None or cap is None or size > maxchars:
            return None
        if cap < 8:
            b = self.raw(addr, size * 2)  # 内联缓冲起点就是 addr
        else:
            ptr = self.u32(addr)
            if not ptr:
                return None
            b = self.raw(ptr, size * 2)
        return None if b is None else b.decode('utf-16-le', 'replace')


def scan_vtable(h, reader, needle=0xCB9EDC, limit_mb=4000):
    """在目标进程里扫 dword == needle 的位置 —— 找 vtable 指针，直接定位 20 字节下载器对象。

    比"顺着某个全局 + 固定偏移"可靠：那个偏移挂在哪个对象上没静态确认过，
    猜错会读到 0（实际踩过一次）。
    """
    class MBI(ctypes.Structure):
        _fields_ = [('BaseAddress', ctypes.c_ulonglong), ('AllocationBase', ctypes.c_ulonglong),
                    ('AllocationProtect', w.DWORD), ('a1', w.DWORD),
                    ('RegionSize', ctypes.c_ulonglong), ('State', w.DWORD),
                    ('Protect', w.DWORD), ('Type', w.DWORD), ('a2', w.DWORD)]

    k32.VirtualQueryEx.argtypes = [w.HANDLE, w.LPCVOID, ctypes.POINTER(MBI), ctypes.c_size_t]
    k32.VirtualQueryEx.restype = ctypes.c_size_t

    pat = needle.to_bytes(4, 'little')
    hits = []
    cur = 0
    total = 0
    mbi = MBI()
    while cur < 0x7FFFFFFF and total < limit_mb * 1024 * 1024:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(cur), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base, size, state, prot = mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect
        if state == 0x1000 and prot in (0x04, 0x40, 0x02, 0x20, 0x80):
            step = 0x10000
            off = 0
            while off < size:
                chunk = reader.raw(base + off, min(step, size - off))
                if chunk:
                    total += len(chunk)
                    i = chunk.find(pat)
                    while i >= 0:
                        hits.append(base + off + i)
                        i = chunk.find(pat, i + 4)
                off += step
        cur = base + size
    return hits, total


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=int, default=0)
    ap.add_argument('--scan', nargs='?', const='0xcb9edc', default=None,
                    help='扫描堆里等于该值的 dword（默认 0xcb9edc = 下载器 vtable）')
    ap.add_argument('--at', default='', help='直接读这个地址的对象（0x...），并列出 map 里的 key')
    ap.add_argument('--dl', action='store_true',
                    help='读 [game+0x580] 的下载器（game = [0x1161F28]）并展开队列，'
                         '同时对比 [session+0x580]')
    ap.add_argument('--node', default='', help='dump 一个 map 节点的原始字节（0x...）')
    ap.add_argument('--poke', default='', help='写 4 字节：ADDR:VALUE（都支持 0x 前缀）')
    ap.add_argument('--clear-tasks', action='store_true',
                    help='把 [game+0x10624] 那个"进度任务列表"清空（end=begin）')
    ap.add_argument('--poke-game', default='',
                    help='按 game 对象偏移写 1 字节：OFF:VAL（OFF 支持 0x 前缀，自动读-改-写 4 字节）')
    ap.add_argument('--poke-flag', action='store_true',
                    help='把 [game+0x10615] 的最低字节置 1（越过「正在取得机师数据」，'
                         '旁边 3 个字节保持原样）')
    ap.add_argument('--watch', type=float, default=0,
                    help='秒数：轮询 [game+0x10615] / +0x10611 并打印变化（预言机模式）')
    ap.add_argument('--vt', action='store_true',
                    help='检查 DAT_01169a04 那个表对象运行期的 vtable（与静态 0xdf8a18 对比）')
    args = ap.parse_args()

    pid = args.pid or find_pid()
    if not pid:
        print('[!] 客户端没在跑')
        return 4
    need = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    if args.poke or args.poke_flag or args.poke_game or args.clear_tasks:
        need |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION
    h = k32.OpenProcess(need, False, pid)
    if not h:
        print(f'[!] OpenProcess 失败 err={ctypes.get_last_error()}（需要管理员）')
        return 5
    r = Reader(h)
    try:
        mz = r.raw(BASE_EXPECT, 2)
        print(f'pid={pid} base=0x{BASE_EXPECT:x} head={mz!r} '
              + ('OK(MZ)' if mz == b'MZ' else 'BAD-BASE'))

        if args.watch:
            import time as _t
            g = r.u32(0x1161F28)
            print('game obj = %s' % (hex(g) if g else g), flush=True)
            if not g:
                return 0
            t0 = _t.time()
            prev = None
            print('watch %.1fs  (flag@+0x10615, flag@+0x10611)' % args.watch, flush=True)
            while _t.time() - t0 < args.watch:
                if not k32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid):
                    print('%s  [!] 进程没了（在这一刻之前最后一条 probe 就是嫌疑）'
                          % _t.strftime('%H:%M:%S'), flush=True)
                    return 0
                a = r.u32(g + 0x10615)
                b = r.u32(g + 0x10611) & 0xFF
                cur = (a, b)
                if cur != prev:
                    print('%s.%03d  10615=%s  10611=%s'
                          % (_t.strftime('%H:%M:%S'), int((_t.time() % 1) * 1000),
                             a, b), flush=True)
                    prev = cur
                _t.sleep(0.05)
            print('%s  watch 结束，最终 10615=%s' % (_t.strftime('%H:%M:%S'), prev), flush=True)
            return 0
        if args.poke_game:
            g = r.u32(0x1161F28)
            if not g:
                print('[!] 取不到 game 对象（DAT_01161f28 = 0）')
                return 0
            off_s, val_s = args.poke_game.split(':')
            off = int(off_s, 0)
            val = int(val_s, 0) & 0xFF
            addr = g + off
            old4 = r.u32(addr)
            # 读的 4 字节就是从 addr 起，目标字节恒为最低字节
            new4 = (old4 & 0xFFFFFF00) | (val & 0xFF)
            buf = new4.to_bytes(4, 'little')
            done = ctypes.c_size_t(0)
            ok = k32.WriteProcessMemory(h, ctypes.c_void_p(addr), buf, 4, ctypes.byref(done))
            after = r.u32(addr)
            print('game=0x%x  [game+0x%x] 0x%08x -> 0x%08x (val=0x%02x) ok=%d err=%d'
                  % (g, off, old4, after, after & 0xFF, ok, ctypes.get_last_error()))
            return 0
        if args.clear_tasks:
            g = r.u32(0x1161F28)
            if not g:
                print('[!] game == 0')
                return 0
            b = r.u32(g + 0x10624)
            e = r.u32(g + 0x1062c)
            c = r.u32(g + 0x10630)
            n = (e - b) // 4 if (e and b and e > b) else 0
            print('任务列表 begin=0x%x end=0x%x cap=0x%x  条目数=%d' % (b, e, c, n))
            if not b or e <= b:
                print('[*] 已经是空列表，无需清')
                return 0
            buf = b.to_bytes(4, 'little')
            done = ctypes.c_size_t(0)
            ok = k32.WriteProcessMemory(h, ctypes.c_void_p(g + 0x1062c), buf, 4,
                                        ctypes.byref(done))
            print('[*] end -> begin: 0x%x -> 0x%x  ok=%d err=%d'
                  % (e, r.u32(g + 0x1062c), ok, ctypes.get_last_error()))
            return 0
        if args.poke_flag:
            g = r.u32(0x1161F28)
            if not g:
                print('[!] 取不到 game 对象（DAT_01161f28 = 0）')
                return 0
            addr = g + 0x10615
            before = r.u32(addr)
            new = (before & 0xFFFFFF00) | 1
            buf = new.to_bytes(4, 'little')
            done = ctypes.c_size_t(0)
            ok = k32.WriteProcessMemory(h, ctypes.c_void_p(addr), buf, 4, ctypes.byref(done))
            after = r.u32(addr)
            print('game=0x%x  [game+0x10615] 0x%08x -> 0x%08x  wrote=%d ok=%d err=%d'
                  % (g, before, after, done.value, ok, ctypes.get_last_error()))
            if after & 0xFF:
                print('[*] 已置位，客户端应离开「正在取得机师数据」')
            else:
                print('[!] 没写进去')
            return 0
        if args.poke:
            a, v = args.poke.split(':')
            addr = int(a, 16) if a.lower().startswith('0x') else int(a)
            val = int(v, 16) if v.lower().startswith('0x') else int(v)
            buf = (val & 0xFFFFFFFF).to_bytes(4, 'little')
            before = r.u32(addr)
            done = ctypes.c_size_t(0)
            ok = k32.WriteProcessMemory(h, ctypes.c_void_p(addr), buf, 4, ctypes.byref(done))
            after = r.u32(addr)
            print('poke 0x%x: %s -> 0x%x  wrote=%d ok=%d err=%d'
                  % (addr, before, after, done.value, ok, ctypes.get_last_error()))
            return 0
        if args.vt:
            def asc(a, n=96):
                b = r.raw(a, n) if a else None
                if not b:
                    return ''
                z = b.find(b'\x00')
                return b[:z if z >= 0 else n].decode('latin1', 'replace')
            for g, label in ((0x1169A04, 'CMechanicOverCustomTable(0x43)'),
                             (0x1169A98, 'CMSMAOverCustomTable(0x41)'),
                             (0x1169A9C, 'CItemOverCustomPointTable(0x42)')):
                obj = r.u32(g)
                print('global 0x%x (%s) -> obj %s' % (g, label, obj if obj is None else hex(obj)))
                if not obj:
                    continue
                vt = r.u32(obj)
                print('   vtable = %s   (static expect 0xdf8a18 / 0xdf89d0-ish)' % (hex(vt) if vt else vt))
                if not vt:
                    continue
                col = r.u32(vt - 4)
                name = ''
                if col:
                    td = r.u32(col + 0xC)
                    name = asc(td + 8) if td else ''
                print('   vtable[-1] = %s  -> class = %r' % (hex(col or 0), name))
                print('   vtable[0..5] = %s' % [hex(x) if x else x for x in (r.u32(vt + 4 * i) for i in range(6))])
            return 0
        if args.node:
            a = int(args.node, 16)
            b = r.raw(a, 0x50)
            print('node @ 0x%x' % a)
            for i in range(0, len(b or b''), 16):
                print('   +0x%02x  %s' % (i, b[i:i + 16].hex(' ')))
            return 0
        if args.dl:
            def dump_dl(tag, obj):
                print('%s @ %s' % (tag, obj if obj is None else hex(obj)))
                if not obj:
                    print('   NULL -> 已析构（done 分支走过），或还没建')
                    return
                print('   vtable = %s  (expect 0xcb9edc)' % r.u32(obj))
                f08 = r.u32(obj + 8)
                print('   +0x08 map sentinel = %s' % (f08 if f08 is None else hex(f08)))
                print('   +0x0C 剩余张数     = %s   (0 means DONE)' % r.u32(obj + 0xC))
                f10 = r.u32(obj + 0x10)
                print('   +0x10 flags        = %s (bit0 pending=%s)'
                      % (f10 if f10 is None else hex(f10), 0 if f10 is None else f10 & 1))
                if not f08:
                    return
                sentinel, names, stack, cur, seen = f08, [], [], r.u32(f08), set()
                while (cur and cur != sentinel and cur not in seen) or stack:
                    while cur and cur != sentinel and cur not in seen:
                        stack.append(cur); seen.add(cur); cur = r.u32(cur)
                    if not stack:
                        break
                    cur = stack.pop()
                    names.append((hex(cur), r.wstr(cur + 0x14), r.u32(cur + 0x0C)))
                    cur = r.u32(cur + 8)
                    if len(names) > 200:
                        break
                print('   map entries: %d' % len(names))
                for i, n in enumerate(names, 1):
                    print('      %3d. %s  name=%r  idx(+0xC)=%s' % (i, n[0], n[1], n[2]))

            g = r.u32(0x1161F28)
            print('game obj (DAT_01161f28) = %s' % (hex(g) if g else g))
            if g:
                dump_dl('[game+0x580]', r.u32(g + 0x580))
            s = r.u32(0x117D380)
            print()
            print('session obj (DAT_0117d380) = %s' % (hex(s) if s else s))
            if s:
                dump_dl('[session+0x580]', r.u32(s + 0x580))

            print()
            print('[*] 表加载分派用的表对象全局（NULL 会让 case 里 mov eax,[ecx] 直接 AV）')
            for gva, label in ((0x1169A48, 'case 0x01 MSMA_WEAPONSET (正常)'),
                               (0x1169A04, 'case 0x43 OVER_CUSTOM_DEVELOP (卡住)'),
                               (0x1169AA0, 'case 0x44'),
                               (0x1169AA4, 'case 0x45')):
                p = r.u32(gva)
                if p is None:
                    print('   0x%08X  读不到' % gva)
                elif p == 0:
                    print('   0x%08X = NULL   <== %s' % (gva, label))
                else:
                    print('   0x%08X = 0x%08X  vtable=0x%08X   %s'
                          % (gva, p, r.u32(p) or 0, label))
            return 0
        if args.at:
            a = int(args.at, 16)
            print('object @ 0x%x  vtable=%s (expect 0xcb9edc)'
                  % (a, hex(r.u32(a) or 0)))
            f08 = r.u32(a + 8)
            print('  +0x08 map sentinel = %s' % (f08 if f08 is None else hex(f08)))
            print('  +0x0C gate/remaining = %s   (0 means DONE)' % r.u32(a + 0xC))
            f10 = r.u32(a + 0x10)
            print('  +0x10 flags = %s (bit0 pending=%s)'
                  % (f10 if f10 is None else hex(f10), 0 if f10 is None else f10 & 1))
            if f08:
                sentinel = f08
                names = []
                stack = []
                cur = r.u32(sentinel)
                seen = set()
                while (cur and cur != sentinel and cur not in seen) or stack:
                    while cur and cur != sentinel and cur not in seen:
                        stack.append(cur); seen.add(cur); cur = r.u32(cur)
                    if not stack:
                        break
                    cur = stack.pop()
                    names.append((hex(cur), r.wstr(cur + 0x14), r.u32(cur + 0x0C)))
                    cur = r.u32(cur + 8)
                    if len(names) > 200:
                        break
                print('  map entries: %d' % len(names))
                for i, n in enumerate(names, 1):
                    print('     %3d. %s  name=%r  idx(+0xC)=%s' % (i, n[0], n[1], n[2]))
            return 0
        if args.scan:
            needle = int(args.scan, 16) if args.scan.lower().startswith('0x') else int(args.scan)
            hits, total = scan_vtable(h, r, needle=needle)
            print('scanned %.1f MB, 0x%x hits: %d' % (total / 1048576.0, needle, len(hits)))
            for a in hits[:12]:
                print('  object @ 0x%x  vtable=%s  +0x08=%s  +0x0C=%s  +0x10=%s'
                      % (a, r.u32(a), r.u32(a + 8), r.u32(a + 0xC), r.u32(a + 0x10)))
            if not hits:
                print('  (none) -> downloader object not present right now')
            return 0
        sess = r.u32(SESSION_GLOBAL)
        print('DAT_0117d380 (session) = %s' % (sess if sess is None else hex(sess)))
        if not sess:
            print('  session not created yet')
            return 0

        tbl = r.u32(sess + TABLES_OFF)
        print('[sess+0x580] (tables) = %s' % (tbl if tbl is None else hex(tbl)))
        if not tbl:
            print('  NULL -> downloader already destroyed (done branch taken)')
            return 0

        vt = r.u32(tbl)
        f08 = r.u32(tbl + 0x08)
        f0c = r.u32(tbl + 0x0C)
        f10 = r.u32(tbl + 0x10)
        print('  vtable = %s  (expect 0xcb9edc %s)'
              % (vt if vt is None else hex(vt), 'OK' if vt == 0xCB9EDC else 'MISMATCH'))
        print('  +0x08 map sentinel = %s' % (f08 if f08 is None else hex(f08)))
        print('  +0x0C gate/done    = %s   <-- 0 means DONE (tick will destroy)' % f0c)
        print('  +0x10 flags        = %s   (bit0 pending=%s)'
              % (f10 if f10 is None else hex(f10), 0 if f10 is None else f10 & 1))

        if f08:
            sentinel = f08
            node = r.u32(sentinel)      # _Myhead->_Left = 最左节点 = begin()
            names = []
            seen = set()
            # 中序走一遍（有界），把 map 里的 key 全列出来
            stack = []
            cur = node
            while (cur and cur != sentinel and cur not in seen) or stack:
                while cur and cur != sentinel and cur not in seen:
                    stack.append(cur)
                    seen.add(cur)
                    cur = r.u32(cur)          # _Left
                if not stack:
                    break
                cur = stack.pop()
                s = r.wstr(cur + 0x14)
                names.append(s)
                cur = r.u32(cur + 8)          # _Right
                if len(names) > 200:
                    break
            print('  map has %d entries:' % len(names))
            for i, n in enumerate(names, 1):
                try:
                    print('     %3d. %s' % (i, n.encode('utf-8', 'replace').decode('utf-8')))
                except Exception:
                    print('     %3d. <unprintable>' % i)
    finally:
        k32.CloseHandle(h)
    return 0


if __name__ == '__main__':
    sys.exit(main())
