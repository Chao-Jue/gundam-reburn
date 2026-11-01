# -*- coding: utf-8 -*-
"""不挂调试器，直接读客户端里的"待下载表"（std::map），把每个节点的
序号（+0x0C）和文件名（std::wstring，buf/ptr @+0x14, size @+0x24, cap @+0x28）打出来。

数据来源：Ghidra 反编译 FUN_00544790（server/decomp_caller.txt）
    this + 8  -> map 哨兵
    node + 0/4/8 = left/parent/right
    node + 0x0C  = 文件序号（switch key）
    node + 0x14  = wstring 内联缓冲 / 指针
    node + 0x24  = wstring size
    node + 0x28  = wstring capacity
    node + 0x2D  = isNil

需要提权（客户端是提权进程）。用法：
    python server/_dump_pending.py [--seconds 900]
每次 map 内容变化就落一行到 server/pending_dump.log。
"""
import ctypes
import ctypes.wintypes as wt
import struct
import subprocess
import sys
import time
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'pending_dump.log')
GLOBALS = [0x1169A48, 0x1169A4C, 0x1169A50, 0x1161F80]   # 几张关心的表对象

k = ctypes.WinDLL('kernel32', use_last_error=True)
k.OpenProcess.restype = wt.HANDLE
k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k.ReadProcessMemory.restype = wt.BOOL
k.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


def log(s):
    with open(OUT, 'a', encoding='utf-8') as f:
        f.write(time.strftime('%H:%M:%S ') + s + '\n')


def find_pid():
    out = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'],
                         capture_output=True).stdout.decode('mbcs', 'ignore')
    for line in out.splitlines():
        if 'GundamOnline_CHINA' in line:
            p = [x.strip('"') for x in line.split('","')]
            if len(p) >= 2 and p[1].isdigit():
                return int(p[1])
    return None


class Mem:
    def __init__(self, h):
        self.h = h

    def rd(self, addr, n):
        if addr < 0x10000 or addr > 0x7FFF0000:
            return None
        b = ctypes.create_string_buffer(n)
        g = ctypes.c_size_t(0)
        ok = k.ReadProcessMemory(wt.HANDLE(self.h), ctypes.c_void_p(addr), b, n,
                                 ctypes.byref(g))
        if not ok or g.value != n:
            return None
        return b.raw

    def u32(self, addr):
        d = self.rd(addr, 4)
        return struct.unpack('<I', d)[0] if d else None

    def u8(self, addr):
        d = self.rd(addr, 1)
        return d[0] if d else None


def read_wstring(m, node):
    """node+0x14 处是 std::wstring（x86 MSVC，cap<8 走内联，否则 +0x14 是堆指针）"""
    cap = m.u32(node + 0x28)
    size = m.u32(node + 0x24)
    if cap is None or size is None:
        return None
    if size > 512:          # 明显不合理，别读
        return '<size=%d 异常>' % size
    if cap < 8:
        base = node + 0x14
    else:
        base = m.u32(node + 0x14)
        if not base:
            return '<ptr=0>'
    raw = m.rd(base, size * 2 + 2)
    if raw is None:
        return '<读失败 base=%08X>' % base
    try:
        return raw.decode('utf-16le', 'replace').split('\x00')[0]
    except Exception:
        return '<解码失败>'


def dump_map(m, obj):
    """从哨兵开始中序遍历，返回 [(index, name, addr), ...]"""
    sentinel = m.u32(obj + 8)
    if not sentinel:
        return None, 'obj+8 = 0'
    res = []
    stack = []
    cur = m.u32(sentinel)          # sentinel.left
    seen = set()
    guard = 0
    while (cur and cur != sentinel) or stack:
        guard += 1
        if guard > 2000:
            return res, '遍历超过 2000 步，可能环'
        while cur and cur != sentinel:
            if cur in seen:
                return res, '发现重复节点 %08X' % cur
            seen.add(cur)
            stack.append(cur)
            cur = m.u32(cur + 0)
        if not stack:
            break
        node = stack.pop()
        idx = m.u32(node + 0x0C)
        nm = read_wstring(m, node)
        res.append((idx, nm, node))
        cur = m.u32(node + 8)
    return res, None


def main():
    secs = 900
    if '--seconds' in sys.argv:
        secs = int(sys.argv[sys.argv.index('--seconds') + 1])
    open(OUT, 'w', encoding='utf-8').close()
    log('start, 监视全局: ' + ', '.join('%08X' % g for g in GLOBALS))
    pid = None
    m = None
    last = {}
    end = time.time() + secs
    while time.time() < end:
        cur = find_pid()
        if not cur:
            if pid:
                log('客户端没了 (pid=%d)' % pid)
                pid = m = None
                last = {}
            time.sleep(0.5)
            continue
        if cur != pid:
            pid = cur
            h = k.OpenProcess(0x10 | 0x400, False, pid)
            log('pid=%d handle=%s (0 的话说明没提权)' % (pid, h))
            if not h:
                return 2
            m = Mem(h)
            last = {}
        for g in GLOBALS:
            obj = m.u32(g)
            if not obj:
                continue
            nodes, err = dump_map(m, obj)
            if nodes is None:
                sig = ('none', err)
            else:
                sig = tuple(nodes)
            if last.get(g) == sig:
                continue
            first = g not in last
            last[g] = sig
            head = ('%08X obj=%08X ' % (g, obj))
            if nodes is None:
                log(head + '[空] ' + (err or ''))
                continue
            log(head + '共 %d 个节点%s' % (len(nodes), ('  (' + err + ')') if err else ''))
            for idx, nm, addr in nodes:
                log('    idx=%-3s  %08X  %r' % (idx, addr, nm))
        time.sleep(0.2)
    log('timeout')
    return 0


if __name__ == '__main__':
    sys.exit(main())
