# -*- coding: utf-8 -*-
"""手动触发的运行时状态采样器（需要管理员）。

用法：右键 server\\probe_state.cmd -> 以管理员身份运行
或者：管理员 cmd 里  python server\\probe_state.py --seconds 900

它每秒采一次样，屏幕上实时滚动，同时把详细内容写进 server/probe_state.log：

  [13:52:01] node=YES idx=1 | rows(weapon_set)=24 | rows(autoexec)=0 | conv=?

  node   : "msma/msma_weapon_set.csv" 的 map 节点还在不在（不在=已被 erase=处理成功）
  idx    : 节点的文件序号（应该是 1）
  rows   : 表对象 +8 那个 map 的行数（>0 说明 Load 真的把行插进去了）
  conv   : 内存里有没有 "#COL0" 的宽字符副本（有=正文被成功转成 UTF-16 了）

只看不改，不挂调试器，不会触发壳的反调试。
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
OUT = os.path.join(HERE, 'probe_state.log')
NAME = 'msma/msma_weapon_set.csv'
G_WPN = 0x1169A48      # CMSMAWeaponSetTable
G_AUTOEXEC = 0x1161F80

_logf = open(OUT, 'a', encoding='utf-8', buffering=1)


def filelog(s):
    _logf.write(time.strftime('%H:%M:%S ') + str(s) + '\n')


def say(s):
    print(s, flush=True)


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


def read_all(h):
    blocks = []
    for base, size in regions(h):
        off = 0
        while off < size:
            n = min(2 << 20, size - off)
            d = rd(h, base + off, n)
            if d:
                blocks.append((base + off, d))
            off += n
    return blocks


def find_nodes(h, blocks, name):
    """返回 [(name_addr, node_addr, idx, size, cap)]"""
    pw = name.encode('utf-16le')
    out = []
    addrs = []
    for base, d in blocks:
        i = 0
        while True:
            j = d.find(pw, i)
            if j < 0:
                break
            addrs.append(base + j)
            i = j + 1
    for addr in addrs[:8]:
        ptr = struct.pack('<I', addr)
        for base, d in blocks:
            i = 0
            while True:
                j = d.find(ptr, i)
                if j < 0:
                    break
                hp = base + j
                node = hp - 0x14
                hdr = rd(h, node, 0x30)
                if hdr:
                    idx = struct.unpack('<I', hdr[0x0C:0x10])[0]
                    size = struct.unpack('<I', hdr[0x24:0x28])[0]
                    cap = struct.unpack('<I', hdr[0x28:0x2C])[0]
                    if size == len(name) and 8 <= cap <= 0x400 and 0 <= idx <= 0x46:
                        out.append((addr, node, idx, size, cap))
                i = j + 1
    return out, addrs


def count_rows(h, glob):
    obj = dw(h, glob)
    if not obj:
        return None, None
    s = dw(h, obj + 8)
    if not s:
        return obj, None
    cnt = 0
    stack = []
    cur = dw(h, s)
    guard = 0
    while (cur and cur != s) or stack:
        guard += 1
        if guard > 4000:
            break
        while cur and cur != s:
            stack.append(cur)
            cur = dw(h, cur + 0)
        if not stack:
            break
        n = stack.pop()
        cnt += 1
        cur = dw(h, n + 8)
        if cnt > 500:
            break
    return obj, cnt


def main():
    secs = 900
    if '--seconds' in sys.argv:
        secs = int(sys.argv[sys.argv.index('--seconds') + 1])
    filelog('==== probe 启动 %s ====' % time.strftime('%Y-%m-%d %H:%M:%S'))
    say('probe_state: 每秒采样一次，%d 秒后自动结束（Ctrl+C 可停）' % secs)
    say('先点"登录"，等界面到"正在取得数据"时看这里的 node/rows 变化')
    say('')
    pid = h = None
    last = None
    end = time.time() + secs
    while time.time() < end:
        cur = find_pid()
        if not cur:
            if pid:
                say('客户端没了')
                filelog('客户端退出')
                pid = h = None
            time.sleep(0.5)
            continue
        if cur != pid:
            pid = cur
            h = k.OpenProcess(0x10 | 0x400, False, pid)
            filelog('pid=%d handle=%s' % (pid, h))
            if not h:
                say('!! OpenProcess 失败 —— 这个窗口不是管理员？')
                filelog('OpenProcess 失败')
                time.sleep(3)
                return 2
            say('已连接 pid=%d' % pid)
        try:
            blocks = read_all(h)
            nodes, addrs = find_nodes(h, blocks, NAME)
            conv = sum(d.count('#COL0'.encode('utf-16le')) for _, d in blocks)
            obj_w, rows_w = count_rows(h, G_WPN)
            obj_a, rows_a = count_rows(h, G_AUTOEXEC)
            tag = ('node=%s idx=%s' % ('YES' if nodes else 'no',
                                       nodes[0][2] if nodes else '-'))
            line = ('[%s] %-14s | rows(weapon_set)=%-5s | rows(autoexec)=%-4s | wide#COL0=%d'
                    % (time.strftime('%H:%M:%S'), tag, rows_w, rows_a, conv))
            if line[10:] != (last or '')[10:] or nodes:
                say(line)
            sig = (bool(nodes), nodes[0][2] if nodes else None, rows_w, rows_a, conv)
            if sig != last:
                filelog(line)
                filelog('   name_hits=%d node=%s' % (
                    len(addrs), ['%08X/idx%d' % (n[1], n[2]) for n in nodes]))
                filelog('   weapon_set obj=%s autoexec obj=%s' % (
                    ('%08X' % obj_w) if obj_w else '0', ('%08X' % obj_a) if obj_a else '0'))
                last = sig
        except Exception:
            filelog('采样异常:\n' + traceback.format_exc())
        time.sleep(1.0)
    say('结束')
    filelog('==== probe 结束 ====')
    return 0


if __name__ == '__main__':
    try:
        rc = main()
    except Exception:
        filelog('!! 异常:\n' + traceback.format_exc())
        rc = 9
    _logf.flush()
    sys.exit(rc)
