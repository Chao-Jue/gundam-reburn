# -*- coding: utf-8 -*-
"""一次性内存扫描：立刻扫，不等待。把所有输出（含异常）写进 server/scan_now.log。

找目标文件名的 UTF-16 / ASCII 副本，以及内存里指向 UTF-16 副本的 dword
（std::map 节点的 wstring 指针），并用节点布局校验：
    node+0x0C = 序号, node+0x14 = wstring ptr, node+0x24 = size, node+0x28 = cap
"""
import ctypes
import ctypes.wintypes as wt
import struct
import subprocess
import sys
import time
import os
import traceback

HERE = r'D:\project\gundam-reburn\server'
OUT = os.path.join(HERE, 'scan_now.log')

_logf = open(OUT, 'w', encoding='utf-8', buffering=1)
sys.stdout = _logf
sys.stderr = _logf


def log(s):
    _logf.write(time.strftime('%H:%M:%S ') + str(s) + '\n')


k = ctypes.WinDLL('kernel32', use_last_error=True)
k.OpenProcess.restype = wt.HANDLE
k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k.ReadProcessMemory.restype = wt.BOOL
k.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]


k.VirtualQueryEx.restype = ctypes.c_size_t
k.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]


def find_pid():
    out = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'],
                         capture_output=True).stdout.decode('mbcs', 'ignore')
    for line in out.splitlines():
        if 'GundamOnline_CHINA' in line:
            p = [x.strip('"') for x in line.split('","')]
            if len(p) >= 2 and p[1].isdigit():
                return int(p[1])
    return None


def rd(h, a, n):
    if a < 0x10000 or a > 0x7FFF0000:
        return None
    b = ctypes.create_string_buffer(n)
    g = ctypes.c_size_t(0)
    if not k.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(a), b, n, ctypes.byref(g)):
        return None
    return b.raw


def regions(h):
    a, mbi = 0x10000, MBI()
    while a < 0x7FFF0000:
        if not k.VirtualQueryEx(wt.HANDLE(h), ctypes.c_void_p(a), ctypes.byref(mbi),
                                ctypes.sizeof(mbi)):
            a += 0x10000
            continue
        base, size = mbi.BaseAddress or 0, mbi.RegionSize or 0
        if size <= 0:
            break
        if (mbi.State == 0x1000 and not (mbi.Protect & 0x100)
                and (mbi.Protect & (0x04 | 0x08 | 0x40))):
            yield base, size
        a = base + size


def main():
    log('=== scan_now 启动 ===')
    pid = find_pid()
    log('pid = %s' % pid)
    if not pid:
        log('客户端没在跑'); return 1
    h = k.OpenProcess(0x10 | 0x400, False, pid)
    log('handle = %s' % h)
    if not h:
        log('打不开进程（需要提权）'); return 2

    names = ['msma/msma_weapon_set.csv', 'autoexec_sv.cfg']
    blocks = []
    t0 = time.time()
    for base, size in regions(h):
        off = 0
        while off < size:
            n = min(2 << 20, size - off)
            d = rd(h, base + off, n)
            if d:
                blocks.append((base + off, d))
            off += n
    log('扫描完成 %.1fs，%d 块，约 %.0f MB' % (time.time() - t0, len(blocks),
                                        sum(len(d) for _, d in blocks) / 1048576.0))

    for name in names:
        pw, pa = name.encode('utf-16le'), name.encode('ascii')
        hw, ha = [], []
        for base, d in blocks:
            i = 0
            while True:
                j = d.find(pw, i)
                if j < 0: break
                hw.append(base + j); i = j + 1
            i = 0
            while True:
                j = d.find(pa, i)
                if j < 0: break
                ha.append(base + j); i = j + 1
        log('')
        log('### %r : UTF-16 命中 %d 处，ASCII 命中 %d 处' % (name, len(hw), len(ha)))
        log('    UTF-16 地址: ' + ', '.join('%08X' % a for a in hw[:12]))
        log('    ASCII  地址: ' + ', '.join('%08X' % a for a in ha[:12]))

        for addr in hw[:10]:
            ptr = struct.pack('<I', addr)
            holders = []
            for base, d in blocks:
                i = 0
                while True:
                    j = d.find(ptr, i)
                    if j < 0: break
                    holders.append(base + j); i = j + 1
            log('  --- 名字 @%08X : 指向它的 dword 有 %d 个 ---' % (addr, len(holders)))
            for hp in holders[:8]:
                node = hp - 0x14
                hdr = rd(h, node, 0x40)
                if not hdr:
                    log('      holder %08X  node %08X 读不到' % (hp, node))
                    continue
                idx, size, cap = (struct.unpack('<I', hdr[0x0C:0x10])[0],
                                  struct.unpack('<I', hdr[0x24:0x28])[0],
                                  struct.unpack('<I', hdr[0x28:0x2C])[0])
                flag = '  ★ 像 map 节点' if (size == len(name) and 8 <= cap <= 0x400
                                          and 0 <= idx <= 0x46) else ''
                log('      holder %08X -> node %08X  idx=%d size=%d cap=%d isNil=%d%s'
                    % (hp, node, idx, size, cap, hdr[0x2D], flag))
                log('        hdr: ' + hdr[:0x30].hex(' '))
    log('=== 完成 ===')
    return 0


if __name__ == '__main__':
    try:
        rc = main()
    except Exception:
        log('!! 异常:\n' + traceback.format_exc())
        rc = 9
    log('exit=%d' % rc)
    _logf.flush()
