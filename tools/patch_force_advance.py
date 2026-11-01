# -*- coding: utf-8 -*-
"""强制推进：把 0x5448F4 的 `jne 0x544E07`（处理失败就返回）改成无条件 jmp 0x544DD7
（公共尾部：erase 待下载节点 + 置标志）。

效果：不管 0xA46480 返回什么，都把节点删掉 → 队列继续往下走。

    python tools/patch_force_advance.py [--pid N] [--revert]
"""
import ctypes
import ctypes.wintypes as wt
import struct
import subprocess
import sys
import time

ADDR = 0x5448F4
TARGET = 0x544DD7
ORIG = bytes.fromhex('0f850d050000')

k = ctypes.WinDLL('kernel32', use_last_error=True)
k.OpenProcess.restype = wt.HANDLE
k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k.ReadProcessMemory.restype = wt.BOOL
k.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k.WriteProcessMemory.restype = wt.BOOL
k.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                 ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

import os
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'server',
                   'patch_force.log')
_lf = open(LOG, 'a', encoding='utf-8', buffering=1)


def p(s):
    print(s, flush=True)
    _lf.write(time.strftime('%H:%M:%S ') + str(s) + '\n')


def find_pid():
    out = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'],
                         capture_output=True).stdout.decode('mbcs', 'ignore')
    for line in out.splitlines():
        if 'GundamOnline_CHINA' in line:
            q = [x.strip('"') for x in line.split('","')]
            if len(q) >= 2 and q[1].isdigit():
                return int(q[1])
    return None


def main():
    pid = int(sys.argv[sys.argv.index('--pid') + 1]) if '--pid' in sys.argv else find_pid()
    p('pid = %s' % pid)
    if not pid:
        return 1
    h = k.OpenProcess(0x0010 | 0x0020 | 0x0008 | 0x0400, False, pid)
    p('handle = %s' % h)
    if not h:
        p('打不开进程（需要管理员）')
        return 2

    def rd(a, n):
        b = ctypes.create_string_buffer(n)
        g = ctypes.c_size_t(0)
        k.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(a), b, n, ctypes.byref(g))
        return b.raw[:g.value]

    before = rd(ADDR, 6)
    p('before: ' + before.hex(' '))
    if before != ORIG and before[:2] != b'\xe9\xde':
        p('!! 字节不是预期，既不是原指令也不是已打过的补丁')
        return 3

    new = ORIG if '--revert' in sys.argv else (b'\xE9' + struct.pack(
        '<i', TARGET - (ADDR + 5)) + b'\x90')
    old = wt.DWORD(0)
    k.VirtualProtect(ctypes.c_void_p(ADDR), 6, 0x40, ctypes.byref(old))
    buf = ctypes.create_string_buffer(new, len(new))
    g = ctypes.c_size_t(0)
    ok = k.WriteProcessMemory(wt.HANDLE(h), ctypes.c_void_p(ADDR), buf, len(new),
                              ctypes.byref(g))
    k.VirtualProtect(ctypes.c_void_p(ADDR), 6, old.value, ctypes.byref(old))
    p('new   : ' + new.hex(' ') + ('  (revert)' if '--revert' in sys.argv
                                   else '  -> 目标 %08X' % TARGET))
    p('write = %s  after = %s' % (ok, rd(ADDR, 6).hex(' ')))
    for i in range(3):
        time.sleep(3)
        p('  +%ds 存活=%s' % ((i + 1) * 3, bool(rd(ADDR, 1))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
