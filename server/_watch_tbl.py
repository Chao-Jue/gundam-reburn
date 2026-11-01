# -*- coding: utf-8 -*-
"""不挂调试器：轮询表对象，记录它有没有变化（判断 Load 到底跑没跑）。"""
import ctypes, ctypes.wintypes as wt, struct, subprocess, time, os

k = ctypes.WinDLL('kernel32', use_last_error=True); k.OpenProcess.restype = wt.HANDLE
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tbl_watch.log')
GLOBAL = 0x1169A48

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

def main():
    open(OUT,'w',encoding='utf-8').close()
    log('watch start')
    last = {}
    h = None; pid = None
    t_end = time.time() + 900
    while time.time() < t_end:
        cur = find_pid()
        if not cur:
            if pid: log('客户端没了 (pid=%d)' % pid); pid=None; h=None
            time.sleep(0.5); continue
        if cur != pid:
            pid = cur; h = k.OpenProcess(0x10, False, pid)
            log('新进程 pid=%d handle=%s' % (pid, h))
        if not h: time.sleep(0.5); continue
        b = ctypes.create_string_buffer(4); g = ctypes.c_size_t(0)
        if not k.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(GLOBAL), b, 4, ctypes.byref(g)):
            time.sleep(0.5); continue
        obj = struct.unpack('<I', b.raw)[0]
        if obj == 0:
            time.sleep(0.3); continue
        d = ctypes.create_string_buffer(0x40); g2 = ctypes.c_size_t(0)
        if not k.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(obj), d, 0x40, ctypes.byref(g2)):
            time.sleep(0.3); continue
        words = struct.unpack('<16I', d.raw)
        sig = d.raw.hex()
        # 再读 +8 指向的容器，一起做签名
        cptr = words[2]
        cbuf = b''
        if 0x10000 < cptr < 0x7FFF0000:
            cb = ctypes.create_string_buffer(0x40); g3 = ctypes.c_size_t(0)
            if k.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(cptr), cb, 0x40, ctypes.byref(g3)):
                cbuf = cb.raw
        sig = sig + '|' + cbuf.hex()
        if last.get(obj) != sig:
            first = obj not in last
            last[obj] = sig
            log(('obj %08X 初始: ' if first else 'obj %08X 变化: ') % obj +
                ' '.join('%08X'%w for w in words))
            if cbuf:
                cw = struct.unpack('<16I', cbuf)
                log('   容器 %08X: %s' % (cptr, ' '.join('%08X'%w for w in cw)))
        time.sleep(0.25)
    log('watch timeout')

main()
