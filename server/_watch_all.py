# -*- coding: utf-8 -*-
"""不挂调试器：同时监视全部 68 个表对象，看哪个变了（= 回复被派发到哪张表）。"""
import ctypes, ctypes.wintypes as wt, struct, subprocess, time, os, json

k = ctypes.WinDLL('kernel32', use_last_error=True); k.OpenProcess.restype = wt.HANDLE
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'tbl_watch_all.log')
GLOBALS = json.load(open(os.path.join(HERE, '_globals.json'), encoding='utf-8'))

def log(s):
    with open(OUT, 'a', encoding='utf-8') as f:
        f.write(time.strftime('%H:%M:%S ') + s + '\n')

def find_pid():
    out = subprocess.run(['tasklist','/FO','CSV','/NH'], capture_output=True).stdout.decode('mbcs','ignore')
    for line in out.splitlines():
        if 'GundamOnline_CHINA' in line:
            p = [x.strip('"') for x in line.split('","')]
            if len(p) >= 2 and p[1].isdigit(): return int(p[1])
    return None

def rd(h, a, n):
    b = ctypes.create_string_buffer(n); g = ctypes.c_size_t(0)
    if k.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(a), b, n, ctypes.byref(g)) and g.value == n:
        return b.raw
    return None

def sig_of(h, glob):
    raw = rd(h, glob, 4)
    if not raw: return None, None
    obj = struct.unpack('<I', raw)[0]
    if obj == 0: return None, None
    body = rd(h, obj, 0x30)
    if not body: return None, None
    words = struct.unpack('<12I', body)
    cptr = words[2]
    extra = b''
    if 0x10000 < cptr < 0x7FFF0000:
        c = rd(h, cptr, 0x30)
        if c: extra = c
    return obj, body + extra

def main():
    open(OUT, 'w', encoding='utf-8').close()
    log('watch-all start, %d globals' % len(GLOBALS))
    last = {}
    pid = h = None
    end = time.time() + 900
    while time.time() < end:
        cur = find_pid()
        if not cur:
            if pid: log('客户端没了 (pid=%d)' % pid); pid = h = None
            time.sleep(0.5); continue
        if cur != pid:
            pid = cur; h = k.OpenProcess(0x10, False, pid)
            last = {}
            log('新进程 pid=%d handle=%s' % (pid, h))
        if not h: time.sleep(0.5); continue
        for idx, g, cls, fname in GLOBALS:
            obj, sig = sig_of(h, int(g, 16))
            if not sig: continue
            key = (g, obj)
            if last.get(key) != sig:
                if key in last and last[key] is not None:
                    log('★ 变化 idx=%d %s (%s) obj=%08X' % (idx, cls, fname, obj))
                    log('   旧: %s' % last[key].hex()[:96])
                    log('   新: %s' % sig.hex()[:96])
                last[key] = sig
        time.sleep(0.3)
    log('timeout')

main()
