# -*- coding: utf-8 -*-
"""触发式内存扫描：等 fake_auth.log 里出现目标表请求 → 等 N 秒 → 扫全内存，
找 "目标文件名" 的 UTF-16 副本，以及指向它的指针（= std::map 节点的 wstring 字段）。

节点布局（来自 FUN_00544790 反编译，见 server/decomp_caller.txt）：
    node+0x00/04/08 = left/parent/right
    node+0x0C       = 文件序号（switch key）
    node+0x14       = wstring buf/ptr
    node+0x24       = wstring size
    node+0x28       = wstring capacity
    node+0x2D       = isNil
若某处 M 存着 dword == 名字地址，则 node = M - 0x14，可用 [node+0x24]==len 验证。

需要提权（客户端是提权进程）。用法：
    python server/_find_node.py --name msma/msma_weapon_set.csv
"""
import ctypes
import ctypes.wintypes as wt
import struct
import subprocess
import sys
import time
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'find_node.log')
LOGF = os.path.join(HERE, 'fake_auth.log')

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


def log(s):
    with open(OUT, 'a', encoding='utf-8') as f:
        f.write(time.strftime('%H:%M:%S ') + s + '\n')
    print(s, flush=True)


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


def scan_blocks(h):
    for base, size in regions(h):
        off = 0
        while off < size:
            n = min(2 << 20, size - off)
            d = rd(h, base + off, n)
            if d:
                yield base + off, d
            off += n


def wide(s):
    return s.encode('utf-16le')


def main():
    name = 'msma/msma_weapon_set.csv'
    if '--name' in sys.argv:
        name = sys.argv[sys.argv.index('--name') + 1]
    wait = 8.0
    if '--wait' in sys.argv:
        wait = float(sys.argv[sys.argv.index('--wait') + 1])

    open(OUT, 'w', encoding='utf-8').close()
    log('=== find_node 启动，目标 %r ===' % name)
    mark = os.path.getsize(LOGF) if os.path.exists(LOGF) else 0
    pid = h = None
    trig = False
    end = time.time() + 1200
    while time.time() < end:
        cur = find_pid()
        if cur and cur != pid:
            pid = cur
            h = k.OpenProcess(0x10 | 0x400, False, pid)
            mark = os.path.getsize(LOGF) if os.path.exists(LOGF) else 0
            log('pid=%d handle=%s' % (pid, h))
            if not h:
                log('!! 打不开进程，说明没提权')
                return 2
        if h and not trig:
            try:
                with open(LOGF, 'rb') as f:
                    f.seek(mark)
                    new = f.read().decode('utf-8', 'replace')
            except Exception:
                new = ''
            if name in new:
                trig = True
                log('检测到 %r 请求，等 %.0fs 让客户端处理完' % (name, wait))
            else:
                mark = os.path.getsize(LOGF) if os.path.exists(LOGF) else 0
                time.sleep(0.3)
                continue
        if not trig:
            time.sleep(0.3)
            continue

        time.sleep(wait)
        log('开始扫描…')
        t0 = time.time()
        pat_w = wide(name)
        pat_a = name.encode('ascii')
        blocks = []
        hits_w = []
        hits_a = []
        for base, d in scan_blocks(h):
            blocks.append((base, d))
            i = 0
            while True:
                j = d.find(pat_w, i)
                if j < 0:
                    break
                hits_w.append((base + j, 'wide'))
                i = j + 1
            i = 0
            while True:
                j = d.find(pat_a, i)
                if j < 0:
                    break
                hits_a.append((base + j, 'ascii'))
                i = j + 1
        log('扫描完成 %.1fs，%d 块；UTF-16 命中 %d 处，ASCII 命中 %d 处'
            % (time.time() - t0, len(blocks), len(hits_w), len(hits_a)))

        # 对每个 UTF-16 命中，找内存里是否有 dword 指向它
        for addr, _ in hits_w[:12]:
            log('--- 名字 @%08X ---' % addr)
            pre = rd(h, addr - 0x20, 0x20 + len(pat_w) + 0x20)
            if pre:
                log('   附近: ' + pre.hex(' '))
            ptr = struct.pack('<I', addr)
            holders = []
            for base, d in blocks:
                i = 0
                while True:
                    j = d.find(ptr, i)
                    if j < 0:
                        break
                    holders.append(base + j)
                    i = j + 1
            if not holders:
                log('   没有任何指针指向它（← 说明它不在 std::map 节点里）')
            for hpos in holders[:6]:
                node = hpos - 0x14
                hdr = rd(h, node, 0x40)
                if not hdr:
                    log('   持有者 %08X 但 node=%08X 读不到' % (hpos, node))
                    continue
                idx = struct.unpack('<I', hdr[0x0C:0x10])[0]
                size = struct.unpack('<I', hdr[0x24:0x28])[0]
                cap = struct.unpack('<I', hdr[0x28:0x2C])[0]
                log('   持有者 @%08X -> node %08X  idx=%d size=%d cap=%d  isNil=%d'
                    % (hpos, node, idx, size, cap, hdr[0x2D]))
                log('      node+0x00..: ' + hdr[:0x30].hex(' '))
        return 0
    log('超时，没看到目标请求')
    return 1


if __name__ == '__main__':
    sys.exit(main())
