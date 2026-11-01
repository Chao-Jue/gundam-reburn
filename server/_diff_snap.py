# -*- coding: utf-8 -*-
"""整块内存差分：autoexec 请求时拍快照 A，msma 回复后 3 秒拍快照 B，diff 出变化的块。
不依赖任何结构假设，也不需要调试器。"""
import ctypes
import ctypes.wintypes as wt
import hashlib
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'mem_diff.log')
BLK = 0x10000

k = ctypes.WinDLL('kernel32', use_last_error=True)


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]


k.OpenProcess.restype = wt.HANDLE
k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k.VirtualQueryEx.restype = ctypes.c_size_t
k.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
k.ReadProcessMemory.restype = wt.BOOL
k.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


def log(s):
    with open(OUT, 'a', encoding='utf-8') as f:
        f.write(time.strftime('%H:%M:%S ') + s + '\n')
    print(s, flush=True)


def find_pid():
    o = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'], capture_output=True).stdout.decode('mbcs', 'ignore')
    for line in o.splitlines():
        if 'GundamOnline_CHINA' in line:
            p = [x.strip('"') for x in line.split('","')]
            if len(p) >= 2 and p[1].isdigit():
                return int(p[1])
    return None


LO, HI = 0x0E000000, 0x30000000

def regions(h):
    a, mbi = LO, MBI()
    while a < HI:
        if not k.VirtualQueryEx(wt.HANDLE(h), ctypes.c_void_p(a), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            a += 0x10000
            continue
        base, size = mbi.BaseAddress or 0, mbi.RegionSize or 0
        if size <= 0:
            break
        if (mbi.State == 0x1000 and not (mbi.Protect & 0x100)
                and (mbi.Protect & (0x04 | 0x08 | 0x40))):
            yield base, size
        a = base + size


def rd(h, a, n):
    b = ctypes.create_string_buffer(n)
    g = ctypes.c_size_t(0)
    if k.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(a), b, n, ctypes.byref(g)) and g.value == n:
        return b.raw
    return None


def snap(h):
    out = {}
    for base, size in regions(h):
        off = 0
        while off < size:
            n = min(BLK, size - off)
            d = rd(h, base + off, n)
            if d:
                out[base + off] = hashlib.blake2b(d, digest_size=8).digest()
            off += n
    return out


def main():
    open(OUT, 'w', encoding='utf-8').close()
    log('diff watch start (等 msma 请求 → 拍 A → 等 12s → 拍 B)')
    logf = os.path.join(HERE, 'fake_auth.log')
    mark = os.path.getsize(logf)
    pid = h = None
    end = time.time() + 900
    while time.time() < end:
        cur = find_pid()
        if cur and cur != pid:
            pid = cur
            h = k.OpenProcess(0x10 | 0x400, False, pid)
            log('pid=%d handle=%s' % (pid, h))
        if not h:
            time.sleep(0.3); continue
        try:
            with open(logf, 'rb') as f:
                f.seek(mark)
                new_txt = f.read().decode('utf-8', 'replace')
        except Exception:
            new_txt = ''
        if 'msma/msma_weapon_set.csv' in new_txt:
            log('检测到 msma 请求（服务端会延迟回复），立刻拍 A')
            A = snap(h)
            log('快照A 完成，%d 块' % len(A))
            time.sleep(12)
            B = snap(h)
            log('快照B 完成，%d 块' % len(B))
            changed = sorted(x for x in set(A) | set(B) if A.get(x) != B.get(x))
            log('变化块数: %d' % len(changed))
            for addr in changed[:80]:
                log('  变化 @%08X' % addr)
            return 0
        mark = os.path.getsize(logf)
        time.sleep(0.2)
    log('timeout')
    return 1


if __name__ == '__main__':
    sys.exit(main())
