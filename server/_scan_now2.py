# -*- coding: utf-8 -*-
"""第二轮运行时取证（提权，一次性）。输出 server/scan_now2.log。

1) 走节点 0x2337FF90 的 parent 链找到 std::map 哨兵，中序遍历，dump 整个"待下载表"
2) 读 [0x1169A48] 表对象，走它的 +8 map，数行数（判断 Load 到底跑没跑）
3) 搜正文痕迹：宽字符 "#COL0"（我们占位表头）以及 autoexec 的内容特征
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
OUT = os.path.join(HERE, 'scan_now2.log')
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


def dw(h, a):
    d = rd(h, a, 4)
    return struct.unpack('<I', d)[0] if d else None


def wstr(h, node):
    cap = dw(h, node + 0x28)
    size = dw(h, node + 0x24)
    if cap is None or size is None or size > 512:
        return None
    base = node + 0x14 if cap < 8 else dw(h, node + 0x14)
    if not base:
        return None
    d = rd(h, base, size * 2 + 2)
    if not d:
        return None
    return d.decode('utf-16le', 'replace').split('\x00')[0]


def find_sentinel(h, node):
    """沿 parent 往上找 2-cycle：S.parent = R 且 R.parent = S"""
    cur = node
    for _ in range(300):
        p = dw(h, cur + 4)
        if not p:
            return None
        pp = dw(h, p + 4)
        if pp == cur:
            return p
        cur = p
    return None


def inorder(h, sentinel, limit=400):
    """std::map 中序：从 sentinel.left 起，null 用 sentinel 表示"""
    out = []
    stack = []
    cur = dw(h, sentinel)
    guard = 0
    while (cur and cur != sentinel) or stack:
        guard += 1
        if guard > 4 * limit + 200:
            out.append(('ERR', '遍历步数超限', 0))
            break
        while cur and cur != sentinel:
            stack.append(cur)
            cur = dw(h, cur + 0)
        if not stack:
            break
        n = stack.pop()
        out.append(n)
        cur = dw(h, n + 8)
        if len(out) >= limit:
            break
    return out


def main():
    log('=== scan_now2 启动 ===')
    pid = find_pid()
    log('pid = %s' % pid)
    if not pid:
        return 1
    h = k.OpenProcess(0x10 | 0x400, False, pid)
    log('handle = %s' % h)
    if not h:
        return 2

    # ---- 1) 待下载表 ----
    NODE = 0x2337FF90
    log('')
    log('## 1) 待下载表（从已知节点 %08X 上溯）' % NODE)
    cur = rd(h, NODE, 0x30)
    if not cur:
        log('   节点读不到（可能已被 erase 或地址变了）')
    else:
        log('   node hdr: ' + cur.hex(' '))
        s = find_sentinel(h, NODE)
        log('   哨兵 = %s' % ('%08X' % s if s else '没找到'))
        if s:
            log('   哨兵: ' + (rd(h, s, 0x30) or b'').hex(' '))
            nodes = inorder(h, s)
            log('   共 %d 个待下载项' % len(nodes))
            for n in nodes:
                if isinstance(n, tuple):
                    log('     ' + str(n)); continue
                idx = dw(h, n + 0x0C)
                nm = wstr(h, n)
                log('     idx=%-3s node=%08X  %r' % (idx, n, nm))

    # ---- 2) 表对象的行 map ----
    log('')
    log('## 2) 表对象行数（判断 Load 跑没跑）')
    for g, label in ((0x1169A48, 'CMSMAWeaponSetTable'), (0x1161F80, 'autoexec(索引0)')):
        obj = dw(h, g)
        log('   [%08X] = %s  (%s)' % (g, ('%08X' % obj) if obj else '0', label))
        if not obj:
            continue
        hdr = rd(h, obj, 0x20)
        if hdr:
            log('     obj: ' + hdr.hex(' '))
        s = dw(h, obj + 8)
        log('     +8 = %s' % (('%08X' % s) if s else '0'))
        if not s:
            continue
        sn = rd(h, s, 0x30)
        if sn:
            log('     哨兵: ' + sn.hex(' '))
        nodes = inorder(h, s, 200)
        log('     行数 = %d' % len(nodes))
        for n in nodes[:5]:
            if isinstance(n, tuple):
                continue
            log('       node=%08X  +0x0C=%s  name=%r'
                % (n, dw(h, n + 0x0C), wstr(h, n)))

    # ---- 3) 正文痕迹 ----
    log('')
    log('## 3) 正文痕迹（宽字符 "#COL0"）')
    def regions():
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

    pats = [('#COL0'.encode('utf-16le'), '宽 #COL0'),
            ('#COL0'.encode('ascii'), '窄 #COL0'),
            ('#'.encode('utf-16le') + b'\x00\x00' + 'C'.encode('utf-16le'), '宽 #\\0C')]
    t0 = time.time()
    for base, size in regions():
        off = 0
        while off < size:
            n = min(2 << 20, size - off)
            d = rd(h, base + off, n)
            if d:
                for pat, tag in pats:
                    i = 0
                    cnt = 0
                    while cnt < 4:
                        j = d.find(pat, i)
                        if j < 0:
                            break
                        log('   %s @%08X' % (tag, base + off + j))
                        i = j + 1
                        cnt += 1
            off += n
    log('   扫完 %.1fs' % (time.time() - t0))
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
