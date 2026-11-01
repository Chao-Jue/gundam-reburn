# -*- coding: utf-8 -*-
"""读 0x544790 分派表里用到的表对象全局（0x1169a48 等），拿 vtable。"""
import ctypes, ctypes.wintypes as wt, struct, subprocess, sys, time

k = ctypes.WinDLL('kernel32', use_last_error=True)
k.OpenProcess.restype = wt.HANDLE

def find_pid():
    out = subprocess.run(['tasklist','/FO','CSV','/NH'], capture_output=True).stdout.decode('mbcs','ignore')
    for line in out.splitlines():
        if 'GundamOnline_CHINA' in line:
            p = [x.strip('"') for x in line.split('","')]
            if len(p) >= 2 and p[1].isdigit():
                return int(p[1])
    return None

def rd(h, a, n):
    b = ctypes.create_string_buffer(n); g = ctypes.c_size_t(0)
    ok = k.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(a), b, n, ctypes.byref(g))
    return b.raw[:g.value] if ok else None

def main():
    for _ in range(180):
        pid = find_pid()
        if not pid:
            time.sleep(2); continue
        h = k.OpenProcess(0x10 | 0x0400, False, pid)
        if not h:
            time.sleep(3); continue
        d = rd(h, 0x1169a30, 0x40)
        if not d:
            time.sleep(3); continue
        print('PID=%d' % pid, flush=True)
        for p in range(0, len(d), 16):
            seg = d[p:p+16]
            print('  %08X  %s' % (0x1169a30+p, ' '.join('%02x'%c for c in seg)), flush=True)
        for g in (0x1169a40, 0x1169a44, 0x1169a48, 0x1169a4c, 0x1169a50, 0x1169a54):
            v = rd(h, g, 4)
            if not v: continue
            ptr = struct.unpack('<I', v)[0]
            vt = 0
            if ptr:
                vs = rd(h, ptr, 4)
                if vs: vt = struct.unpack('<I', vs)[0]
            print('  global %08X -> obj %08X vtable %08X' % (g, ptr, vt), flush=True)
        return 0
    print('没等到可读的实例')
    return 1

sys.exit(main())
