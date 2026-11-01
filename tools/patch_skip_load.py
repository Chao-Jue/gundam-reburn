# -*- coding: utf-8 -*-
"""把 0x5448FA（switch 表序号 / 调各表 Load 的地方）改成直接跳到 0x544DD7（公共尾部：
FUN_009EBC20 / memset / std::map::erase / 置已处理标志）。

效果：收到任何表的正文后都不再调用加载器，直接 erase 待下载节点 → 队列推进。

只改内存，5 个字节；客户端重启即恢复。需要管理员。

    python tools/patch_skip_load.py --pid 1234 [--revert]
"""
import ctypes
import ctypes.wintypes as wt
import struct
import subprocess
import sys
import time

import os

_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'server',
                    'patch_skip.log')


class _Tee:
    def __init__(self, path):
        self.f = open(path, 'a', encoding='utf-8', buffering=1)
        self.o = sys.stdout

    def write(self, s):
        try:
            self.o.write(s)
        except Exception:
            pass
        self.f.write(s)

    def flush(self):
        try:
            self.o.flush()
        except Exception:
            pass
        self.f.flush()


if sys.stdout and sys.stdout.isatty() is False:
    pass
try:
    sys.stdout = _Tee(_LOG)
except Exception:
    pass

k = ctypes.WinDLL('kernel32', use_last_error=True)
k.OpenProcess.restype = wt.HANDLE
k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k.ReadProcessMemory.restype = wt.BOOL
k.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k.WriteProcessMemory.restype = wt.BOOL
k.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                 ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

ADDR = 0x5448FA
TARGET = 0x544DD7
ORIG = bytes.fromhex('8b460c83f8460f87d1040000'.replace(' ', ''))[:5]   # 8b 46 0c 83 f8


def find_pid():
    out = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'],
                         capture_output=True).stdout.decode('mbcs', 'ignore')
    for line in out.splitlines():
        if 'GundamOnline_CHINA' in line:
            p = [x.strip('"') for x in line.split('","')]
            if len(p) >= 2 and p[1].isdigit():
                return int(p[1])
    return None


def main():
    pid = None
    if '--pid' in sys.argv:
        pid = int(sys.argv[sys.argv.index('--pid') + 1])
    pid = pid or find_pid()
    print('pid =', pid)
    if not pid:
        return 1
    h = k.OpenProcess(0x0010 | 0x0020 | 0x0008 | 0x0400, False, pid)
    print('handle =', h)
    if not h:
        print('打不开进程（需要管理员）')
        return 2

    def rd(a, n):
        b = ctypes.create_string_buffer(n)
        g = ctypes.c_size_t(0)
        k.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(a), b, n, ctypes.byref(g))
        return b.raw[:g.value]

    before = rd(ADDR, 8)
    print('before:', before.hex(' '))
    if before[:5] != b'\x8b\x46\x0c\x83\xf8':
        print('!! 开头不是预期的 mov eax,[esi+0xC]; cmp eax,imm —— 可能壳还没解包，或者地址不对')
        return 3

    if '--revert' in sys.argv:
        old = wt.DWORD(0)
        k.VirtualProtect(ctypes.c_void_p(ADDR), 8, 0x40, ctypes.byref(old))
        # 原样写回：8b 46 0c 83 f8 46 0f 87
        orig = bytes.fromhex('8b460c83f8460f87')
        buf = ctypes.create_string_buffer(orig, len(orig))
        g = ctypes.c_size_t(0)
        ok = k.WriteProcessMemory(wt.HANDLE(h), ctypes.c_void_p(ADDR), buf, len(orig),
                                  ctypes.byref(g))
        k.VirtualProtect(ctypes.c_void_p(ADDR), 8, old.value, ctypes.byref(old))
        print('revert write =', ok, 'after =', rd(ADDR, 8).hex(' '))
        return 0

    rel = TARGET - (ADDR + 5)
    new = b'\xE9' + struct.pack('<i', rel)
    print('new   :', new.hex(' '), '-> 目标 %08X' % (ADDR + 5 + rel))
    old = wt.DWORD(0)
    k.VirtualProtect(ctypes.c_void_p(ADDR), 8, 0x40, ctypes.byref(old))
    print('VirtualProtect old = 0x%X' % old.value)
    buf = ctypes.create_string_buffer(new, len(new))
    g = ctypes.c_size_t(0)
    ok = k.WriteProcessMemory(wt.HANDLE(h), ctypes.c_void_p(ADDR), buf, len(new),
                              ctypes.byref(g))
    k.VirtualProtect(ctypes.c_void_p(ADDR), 8, old.value, ctypes.byref(old))
    print('write =', ok, 'after =', rd(ADDR, 8).hex(' '))
    for t in (2, 5, 10):
        time.sleep(3)
        alive = rt = rd(0x5448FA, 1)
        print('  +%ds 存活=%s' % (t, bool(alive)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
