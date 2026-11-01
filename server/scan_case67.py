# -*- coding: utf-8 -*-
"""卡住时扫内存：找 develop/mechanic_overcustom.csv 的 map 节点。
节点结构（前面实测过）：
    +0x0C = 序号（u32）
    +0x14 = 指向名字（UTF-16）的指针
    +0x24 = 名字长度  +0x28 = 容量
    +0x2C = 颜色位（1=黑）

判读：
    找到节点、序号 == 67  -> 名字查找命中，卡在后面的解包/加载
    找不到节点            -> 该条已被 erase（说明处理成功）或根本没进队列
"""
import ctypes, ctypes.wintypes as wt, struct, subprocess, time, os, sys

k = ctypes.WinDLL('kernel32', use_last_error=True)
k.OpenProcess.restype = wt.HANDLE
k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k.VirtualQueryEx.restype = ctypes.c_size_t
k.ReadProcessMemory.restype = wt.BOOL
k.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'scan_case67.log')


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]


def log(s):
    with open(OUT, 'a', encoding='utf-8') as f:
        f.write(s + '\n')
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


def main():
    open(OUT, 'w', encoding='utf-8').close()
    pid = find_pid()
    if not pid:
        log('没有 GundamOnline_CHINA.exe')
        return 1
    h = k.OpenProcess(0x10 | 0x400, False, pid)
    log('pid=%d handle=%s' % (pid, h))
    if not h:
        log('OpenProcess 失败（err=%d），需要管理员' % ctypes.get_last_error())
        return 2

    def rd(a, n):
        b = ctypes.create_string_buffer(n)
        g = ctypes.c_size_t(0)
        if k.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(a), b, n, ctypes.byref(g)) and g.value == n:
            return b.raw
        return None

    def regions():
        a, mbi = 0x10000, MBI()
        while a < 0x7FFF0000:
            if not k.VirtualQueryEx(wt.HANDLE(h), ctypes.c_void_p(a),
                                    ctypes.byref(mbi), ctypes.sizeof(mbi)):
                a += 0x10000
                continue
            base, size = mbi.BaseAddress or 0, mbi.RegionSize or 0
            if size <= 0:
                break
            if (mbi.State == 0x1000 and not (mbi.Protect & 0x100)
                    and (mbi.Protect & (0x04 | 0x08 | 0x40))):
                yield base, size
            a = base + size

    # 一次性把内存读进来（按块）
    blocks = []
    for base, size in regions():
        off = 0
        while off < size:
            n = min(4 << 20, size - off)
            d = rd(base + off, n)
            if d:
                blocks.append((base + off, d))
            off += n
    total = sum(len(d) for _, d in blocks)
    log('读入 %.0f MB' % (total / 1048576.0))

    TARGETS = ['develop/mechanic_overcustom.csv',
               'msma/msma_weapon_set.csv',
               'mission/mission_xwar_banpick_rule.csv']
    for tgt in TARGETS:
        wide = tgt.encode('utf-16le')
        ascii_ = tgt.encode('ascii')
        print_hits = []
        for base, d in blocks:
            i = 0
            while True:
                j = d.find(wide, i)
                if j < 0:
                    break
                print_hits.append((base + j, 'w'))
                i = j + 1
            i = 0
            while True:
                j = d.find(ascii_, i)
                if j < 0:
                    break
                print_hits.append((base + j, 'a'))
                i = j + 1
        log('')
        log('=== %s ===' % tgt)
        log('  字符串命中 %d 处: %s' % (len(print_hits),
                                        ', '.join('%08X(%s)' % (a, t) for a, t in print_hits[:6])))
        # 找指向它的 dword
        found = 0
        for addr, kind in print_hits[:6]:
            pat = struct.pack('<I', addr)
            for base, d in blocks:
                i = 0
                while True:
                    j = d.find(pat, i)
                    if j < 0:
                        break
                    holder = base + j
                    # holder 应该是 node+0x14
                    node = holder - 0x14
                    raw = rd(node, 0x34)
                    if raw:
                        w = struct.unpack('<13I', raw)
                        idx = w[3]      # +0x0C
                        ptr = w[5]      # +0x14
                        size = w[9]     # +0x24
                        cap = w[10]     # +0x28
                        col = w[11]     # +0x2C
                        if ptr == addr and size == len(tgt):
                            found += 1
                            log('  ★ node %08X : 序号=%d 名字=%08X size=%d cap=%d color=%d'
                                % (node, idx, ptr, size, cap, col))
                    i = j + 1
        log('  合格节点 %d 个' % found)

    log('')
    log('=== 判读 ===')
    log('  develop/mechanic_overcustom.csv 有节点且有序号 67')
    log('     -> 名字查找命中，卡点在解包 0xA46480 或 Load 链')
    log('  没有节点 -> 已被 erase（处理成功）或该条根本没进队列')
    return 0


if __name__ == '__main__':
    sys.exit(main())
