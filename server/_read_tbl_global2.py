# -*- coding: utf-8 -*-
"""常驻读取器：每 0.3s 读一次表对象全局，非零就落盘（提权运行）。"""
import ctypes, ctypes.wintypes as wt, struct, subprocess, time, os, sys

k = ctypes.WinDLL('kernel32', use_last_error=True)
k.OpenProcess.restype = wt.HANDLE
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tbl_global.log')

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

def log(s):
    with open(OUT, 'a', encoding='utf-8') as f:
        f.write(time.strftime('%H:%M:%S ') + s + '\n')

def main():
    open(OUT, 'w', encoding='utf-8').close()
    log('reader start')
    seen = {}
    deadline = time.time() + 900
    while time.time() < deadline:
        pid = find_pid()
        if not pid:
            time.sleep(0.5); continue
        h = k.OpenProcess(0x10, False, pid)
        if not h:
            log('open pid=%d failed err=%d' % (pid, ctypes.get_last_error()))
            time.sleep(2); continue
        d = rd(h, 0x1169a30, 0x40)
        if not d:
            time.sleep(0.5); continue
        nz = [(0x1169a30 + i, d[i]) for i in range(0, len(d), 4) if struct.unpack('<I', d[i:i+4])[0]]
        if nz:
            key = tuple(nz)
            if key != seen.get(pid):
                seen[pid] = key
                lines = []
                for p in range(0, len(d), 16):
                    seg = d[p:p+16]
                    lines.append('  %08X  %s' % (0x1169a30+p, ' '.join('%02x'%c for c in seg)))
                for g in (0x1169a40, 0x1169a44, 0x1169a48, 0x1169a4c, 0x1169a50):
                    v = rd(h, g, 4)
                    if not v: continue
                    ptr = struct.unpack('<I', v)[0]
                    vt = 0
                    if ptr:
                        vs = rd(h, ptr, 4)
                        if vs: vt = struct.unpack('<I', vs)[0]
                    lines.append('  global %08X -> obj %08X vtable %08X' % (g, ptr, vt))
                log('PID=%d 非零！\n' % pid + '\n'.join(lines))
        time.sleep(0.3)
    log('reader timeout')
    return 0

sys.exit(main())
