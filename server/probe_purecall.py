# -*- coding: utf-8 -*-
"""读 case 60..70 用到的表对象全局，打印 vtable / 槽0 / 槽1 / 类名。
槽0 == 0xC11FE7 就是 MSVC 的 _purecall（纯虚调用桩）。

用途：确认 case 67（OVER_CUSTOM_DEVELOP，卡住的那张）到底是不是 purecall。
只读内存，不挂调试器，不会让客户端崩。

用法（需要管理员，因为游戏是提权进程）：
    右键 -> 以管理员身份运行 probe_purecall.cmd
结果写到 probe_purecall.log
"""
import ctypes, ctypes.wintypes as wt, struct, subprocess, time, os, sys

k = ctypes.WinDLL('kernel32', use_last_error=True)
k.OpenProcess.restype = wt.HANDLE
k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k.VirtualQueryEx.restype = ctypes.c_size_t

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'probe_purecall.log')
IMG = os.path.join(HERE, 'img_dump', 'main_GundamOnline_CHINA.exe')
PURECALL = 0xC11FE7

# case 序号 -> (全局地址, 说明)  从跳转表 0x544E3C 的 case 代码里读出来的
CASES = [
    (64, 0x1169A94, 'MODULE_RENTAL'),
    (65, 0x1169A98, 'OVER_CUSTOM'),
    (66, 0x1169A9C, 'OVER_CUSTOM_CUPSULE'),
    (67, 0x1169A04, 'OVER_CUSTOM_DEVELOP  <<< 卡在这'),
    (68, 0x1169AA0, 'MISSION_XWAR_BANPICK'),
    (69, 0x1169AA4, 'MONTHLY_BONUS_REWARD'),
    (70, 0x1169A48, '(对照: MSMA_WEAPONSET, 用槽0)'),
]


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
    # 镜像加载：用于反查类名（只读文件，不碰进程）
    try:
        import pefile
        data = open(IMG, 'rb').read()
        pe = pefile.PE(IMG, fast_load=True)
        BASE = pe.OPTIONAL_HEADER.ImageBase
        SEC = [(s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData),
                s.PointerToRawData) for s in pe.sections]
    except Exception as e:
        data = None
        log('镜像读取失败（类名将不可用）: %s' % e)

    def va2off(va):
        rva = va - BASE
        for sva, sz, raw in SEC:
            if sva <= rva < sva + sz:
                return raw + (rva - sva)
        return None

    def s_dw(va):
        o = va2off(va)
        return struct.unpack('<I', data[o:o + 4])[0] if o is not None else None

    def s_cstr(va):
        o = va2off(va)
        if o is None:
            return None
        e = data.find(b'\0', o)
        return data[o:e].decode('latin1', 'replace') if 0 <= e - o < 200 else None

    def class_of(vt):
        try:
            col = s_dw(vt - 4)
            td = s_dw(col + 0x0C)
            nm = s_cstr(td + 8)
            return nm.replace('.?AV', '').replace('@@', '') if nm else None
        except Exception:
            return None

    pid = find_pid()
    if not pid:
        log('没有找到 GundamOnline_CHINA.exe，请先把客户端起起来')
        return 1
    h = k.OpenProcess(0x10 | 0x400, False, pid)
    log('客户端 pid=%d  handle=%s' % (pid, h))
    if not h:
        log('OpenProcess 失败（err=%d）—— 本脚本需要管理员权限' % ctypes.get_last_error())
        return 2

    def r_u32(a):
        b = ctypes.create_string_buffer(4)
        g = ctypes.c_size_t(0)
        if k.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(a), b, 4, ctypes.byref(g)) and g.value == 4:
            return struct.unpack('<I', b.raw)[0]
        return None

    log('')
    log('槽0 == 0x%08X 表示该对象是 TIndexTable 基类实例（纯虚调用 → 必崩）' % PURECALL)
    log('')
    log('（每个 case 展开所有槽位）')
    verdict = {}
    for cs, gaddr, note in CASES:
        obj = r_u32(gaddr)
        if not obj:
            log('%-4d 0x%08X (全局为空/NULL)                                    %s'
                % (cs, gaddr, note))
            verdict[cs] = None
            continue
        vt = r_u32(obj)
        if not vt:
            log('%-4d 0x%08X 0x%08X  (vtable 读不到)' % (cs, gaddr, obj))
            continue
        slots = [r_u32(vt + 4 * k) for k in range(8)]
        cls = class_of(vt) if vt else None
        log('')
        log('case %d  全局 0x%08X  对象 0x%08X  vtable 0x%08X' % (cs, gaddr, obj, vt))
        log('    类名: %s    %s' % (cls or '?', note))
        for k, e in enumerate(slots):
            mark = ''
            if k == 0: mark = '  <- 行解析器'
            if k == 1: mark = '  <- Load'
            if k == 3: mark = '  <- 写回/插入'
            if k == 5: mark = '  <- 取第0列'
            log('    槽%d: %s%s' % (k, ('%08X' % e) if e else '0        ', mark))
        verdict[cs] = slots[0]

    log('')
    log('=== 判读 ===')
    if verdict.get(67) == PURECALL:
        log('  67 的槽0 是 purecall  -> 只要是"有数据的行"就必须崩，'
            '只能下发 0 行（纯注释 / 空文件）')
    elif verdict.get(67):
        log('  67 的槽0 不是 purecall（= 0x%08X），说明它有真实解析器，'
            '卡点不在纯虚调用' % verdict[67])
    else:
        log('  67 的全局为 NULL -> case 67 一进去就 AV')
    if verdict.get(65) == verdict.get(67):
        log('  注意：65 和 67 的槽0 相同，但实测 65 能过 —— 说明差异不在这里，'
            '需要再查 case 65 与 67 的其它区别')
    return 0


if __name__ == '__main__':
    sys.exit(main())
