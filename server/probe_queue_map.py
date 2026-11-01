# -*- coding: utf-8 -*-
"""读「下载队列」那个 map 的全部成员，验证第 65 张的名字到底在不在里面。

链路（反编译得出）：
    0xA4FAC0  mov ecx,[0x1161F28]        ; manager1（全局）
    0x42DA60  mov ecx,[ecx+0x580]        ; manager2
    0x544790  piVar11 = [manager2+8]     ; map head（哨兵）
              node = *head               ; 第一个节点
              节点结构： +0x00 左  +0x04 父  +0x08 右  +0x0C 序号
                        +0x10 颜色  +0x14 std::wstring(名)
                        +0x24 size  +0x28 cap  +0x2C ...

只读内存，不挂调试器。需要管理员（游戏是提权进程）。
"""
import ctypes, ctypes.wintypes as wt, struct, subprocess, os, sys

k = ctypes.WinDLL('kernel32', use_last_error=True)
k.OpenProcess.restype = wt.HANDLE
k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k.ReadProcessMemory.restype = wt.BOOL
k.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'queue_map.log')
G_MANAGER = 0x1161F28
OFF_MANAGER2 = 0x580
OFF_MAP = 0x08


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
    if not h:
        log('OpenProcess 失败 err=%d（需要管理员）' % ctypes.get_last_error())
        return 2
    log('pid=%d handle=%s' % (pid, h))

    def rd(a, n):
        b = ctypes.create_string_buffer(n)
        g = ctypes.c_size_t(0)
        if k.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(a), b, n, ctypes.byref(g)) and g.value == n:
            return b.raw
        return None

    def u32(a):
        d = rd(a, 4)
        return struct.unpack('<I', d)[0] if d else None

    m1 = u32(G_MANAGER)
    log('[0x%08X] manager1 = %s' % (G_MANAGER, hex(m1) if m1 else 'NULL'))
    if not m1:
        return 3
    m2 = u32(m1 + OFF_MANAGER2)
    log('[manager1+0x%X] manager2 = %s' % (OFF_MANAGER2, hex(m2) if m2 else 'NULL'))
    if not m2:
        return 3
    head = u32(m2 + OFF_MAP)
    log('[manager2+0x%X] map head = %s' % (OFF_MAP, hex(head) if head else 'NULL'))
    if not head:
        return 3

    # 中序遍历：node 的左/父/右在 +0/+4/+8，颜色位在 +0x2D（哨兵标志）
    def is_nil(n):
        b = rd(n + 0x2D, 1)
        return (b is None) or (b[0] != 0)

    def name_of(n):
        size = u32(n + 0x24)
        cap = u32(n + 0x28)
        if size is None or cap is None:
            return None, None
        # std::wstring：cap < 8 走内联（n+0x14 起），否则 n+0x14 存指针
        if cap < 8:
            base = n + 0x14
        else:
            base = u32(n + 0x14)
            if not base:
                return None, size
        raw = rd(base, min(size * 2, 512))
        if not raw:
            return None, size
        try:
            return raw.decode('utf-16le', 'replace'), size
        except Exception:
            return None, size

    # 先走到最左
    first = u32(head + 0x04) or 0    # 根
    for _ in range(200):
        if not first or is_nil(first):
            break
        left = u32(first)
        if not left or is_nil(left):
            break
        first = left

    log('')
    log('=== 下载队列 map 成员（中序遍历）===')
    log('#  节点        序号  名字长度  名字')
    node = first
    seen = set()
    count = 0
    while node and not is_nil(node) and node not in seen and count < 200:
        seen.add(node)
        idx = u32(node + 0x0C)
        nm, size = name_of(node)
        count += 1
        log('%3d 0x%08X  %-5s %-8s  %s' % (count, node,
                                           idx if idx is not None else '?',
                                           size if size is not None else '?',
                                           nm if nm is not None else '<读不到>'))
        # 中序后继
        right = u32(node + 0x08)
        if right and not is_nil(right):
            node = right
            while True:
                left = u32(node) or 0
                if not left or is_nil(left):
                    break
                node = left
        else:
            parent = u32(node + 0x04) or 0
            cur = node
            while parent and not is_nil(parent) and (u32(parent + 0x08) or 0) == cur:
                cur = parent
                parent = u32(parent + 0x04) or 0
            node = parent

    log('')
    log('=== 共 %d 个成员 ===' % count)
    log('注意：如果这里为空，说明这个 manager 不是下载队列所在的 manager（链路推断有误）。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
