# -*- coding: utf-8 -*-
"""一次读全部 67 个 case 的表对象：vtable + 槽 0..7 + 类名，输出 TSV。

目的：看「哪个 case 用了哪份 Load / 插入实现」，确认第 65 张（case 67）
是不是第一次走到 0x9BEC20 这条共享 Load —— 而不是什么"64 上限"。

只读内存，不挂调试器。
"""
import ctypes, ctypes.wintypes as wt, struct, subprocess, os, sys, json

k = ctypes.WinDLL('kernel32', use_last_error=True)
k.OpenProcess.restype = wt.HANDLE
k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k.ReadProcessMemory.restype = wt.BOOL

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'all_cases.log')
IMG = os.path.join(HERE, 'img_dump', 'main_GundamOnline_CHINA.exe')


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
    cases = json.load(open(os.path.join(HERE, '_case_globals.json'), encoding='utf-8'))
    log('# case\tglobal\tobj\tvtable\tslot0\tslot1\tslot2\tslot3\tslot4\tslot5\tclass')

    try:
        import pefile
        data = open(IMG, 'rb').read()
        pe = pefile.PE(IMG, fast_load=True)
        BASE = pe.OPTIONAL_HEADER.ImageBase
        SEC = [(s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData),
                s.PointerToRawData) for s in pe.sections]
    except Exception:
        data = None

    def s_dw(va):
        if data is None:
            return None
        rva = va - BASE
        for sva, sz, raw in SEC:
            if sva <= rva < sva + sz:
                o = raw + (rva - sva)
                return struct.unpack('<I', data[o:o + 4])[0]
        return None

    def s_cstr(va):
        if data is None:
            return None
        rva = va - BASE
        for sva, sz, raw in SEC:
            if sva <= rva < sva + sz:
                o = raw + (rva - sva)
                e = data.find(b'\0', o)
                return data[o:e].decode('latin1', 'replace') if 0 <= e - o < 200 else None
        return None

    def class_of(vt):
        try:
            col = s_dw(vt - 4)
            td = s_dw(col + 0x0C)
            nm = s_cstr(td + 8)
            return nm.replace('.?AV', '').replace('@@', '') if nm else '?'
        except Exception:
            return '?'

    pid = find_pid()
    if not pid:
        log('ERR 没有 GundamOnline_CHINA.exe')
        return 1
    h = k.OpenProcess(0x10 | 0x400, False, pid)
    if not h:
        log('ERR OpenProcess 失败 err=%d（需要管理员）' % ctypes.get_last_error())
        return 2
    log('# pid=%d' % pid)

    def r_u32(a):
        b = ctypes.create_string_buffer(4)
        g = ctypes.c_size_t(0)
        if k.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(a), b, 4, ctypes.byref(g)) and g.value == 4:
            return struct.unpack('<I', b.raw)[0]
        return None

    for cs, gaddr, slotoff in cases:
        obj = r_u32(gaddr)
        if not obj:
            log('%d\t0x%08X\tNULL' % (cs, gaddr))
            continue
        vt = r_u32(obj)
        if not vt:
            log('%d\t0x%08X\t0x%08X\tNOVT' % (cs, gaddr, obj))
            continue
        slots = [(r_u32(vt + 4 * i) or 0) for i in range(6)]
        log('%d\t0x%08X\t0x%08X\t0x%08X\t%s\t%s'
            % (cs, gaddr, obj, vt,
               '\t'.join('%08X' % s for s in slots),
               class_of(vt)))
    log('# done')
    return 0


if __name__ == '__main__':
    sys.exit(main())
