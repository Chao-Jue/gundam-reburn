# -*- coding: utf-8 -*-
"""生成"文件序号 → 表类 → Load → 行解析器"地图。需要提权（客户端是提权进程）。"""
import ctypes, ctypes.wintypes as wt, struct, subprocess, os, csv
import pefile

IMG = r'D:/project/gundam-reburn/server/img_dump/main_GundamOnline_CHINA.exe'
OUT_MD = r'D:/project/gundam-reburn/server/表地图.md'
LIST = r'D:/project/gundam-reburn/server/ref_settings/download_list.csv'

data = open(IMG, 'rb').read()
pe = pefile.PE(IMG, fast_load=True); BASE = pe.OPTIONAL_HEADER.ImageBase
SEC = [(s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData) for s in pe.sections]

def va2off(va):
    rva = va - BASE
    for sva, sz, raw in SEC:
        if sva <= rva < sva + sz:
            return raw + (rva - sva)

def s_dw(va):
    o = va2off(va)
    return struct.unpack('<I', data[o:o+4])[0] if o is not None else None

def s_cstr(va):
    o = va2off(va)
    if o is None: return None
    e = data.find(b'\0', o)
    return data[o:e].decode('latin1', 'replace')

def class_of(vt):
    try:
        col = s_dw(vt - 4)
        td = s_dw(col + 0x0C)
        return s_cstr(td + 8)
    except Exception:
        return None

def row_parser_of(load):
    """在 Load 前 0x60 字节里找 push imm32 ... call 0xB08960。"""
    o = va2off(load)
    if o is None: return None
    code = data[o:o+0x60]
    pushes = []
    for i in range(len(code)-5):
        if code[i] == 0x68:
            pushes.append((load+i, struct.unpack('<I', code[i+1:i+5])[0]))
        if code[i] == 0xE8 and i+5 <= len(code):
            tgt = load + i + 5 + struct.unpack('<i', code[i+1:i+5])[0]
            if tgt == 0xB08960:
                # 往回找最近的 push imm32（回调在 call 前第 3 个参数）
                cand = [p for p in pushes if p[0] < load+i]
                return cand[-3][1] if len(cand) >= 3 else (cand[-1][1] if cand else None)
    return None

# 文件序号 → 文件名
names = []
with open(LIST, encoding='utf-8-sig') as f:
    for row in csv.reader(f):
        if not row or row[0].startswith('#') or len(row) < 2:
            continue
        names.append(row[1].strip())

# 跳转表
TBL, N = 0x544E3C, 0x47
entries = []
for i in range(N):
    ent = s_dw(TBL + 4*i)
    entries.append(ent)

# 运行期读全局
k = ctypes.WinDLL('kernel32', use_last_error=True); k.OpenProcess.restype = wt.HANDLE
def find_pid():
    out = subprocess.run(['tasklist','/FO','CSV','/NH'], capture_output=True).stdout.decode('mbcs','ignore')
    for line in out.splitlines():
        if 'GundamOnline_CHINA' in line:
            p = [x.strip('"') for x in line.split('","')]
            if len(p) >= 2 and p[1].isdigit(): return int(p[1])
pid = find_pid()
if not pid:
    print('客户端没在跑'); raise SystemExit(1)
h = k.OpenProcess(0x10, False, pid)
if not h:
    print('OpenProcess 失败（需要提权运行本脚本）'); raise SystemExit(2)

def r_u32(a):
    b = ctypes.create_string_buffer(4); g = ctypes.c_size_t(0)
    if k.ReadProcessMemory(wt.HANDLE(h), ctypes.c_void_p(a), b, 4, ctypes.byref(g)) and g.value == 4:
        return struct.unpack('<I', b.raw)[0]
    return None

lines = ['# 数据表下载：文件序号 → 表类 → Load → 行解析器', '',
         '> 由 `server/_build_table_map.py` 生成。Load 是 vtable 第 0 槽；行解析器是 Load 里',
         '> 传给通用迭代器 `0xB08960` 的回调。客户端 PID=%d。' % pid, '',
         '| # | 文件名 | 表类 | 全局 | Load | 行解析器 |', '|---|---|---|---|---|---|']
ok = 0
for i, ent in enumerate(entries):
    if not ent:
        continue
    code_off = va2off(ent)
    cand = data[code_off:code_off+0x30]
    glob = None
    if len(cand) > 6 and cand[0] == 0x8B and cand[1] == 0x0D:
        glob = struct.unpack('<I', cand[2:6])[0]
    cls = load = rp = '-'
    if glob:
        obj = r_u32(glob)
        if obj:
            vt = r_u32(obj)
            if vt:
                cls = class_of(vt) or '?'
                load = s_dw(vt) or 0
                if load and load > BASE:
                    rp = row_parser_of(load) or '-'
    nm = names[i] if i < len(names) else '?'
    lines.append('| %d | `%s` | %s | %s | %s | %s |' % (
        i, nm, (cls or '-').replace('.?AV', '').replace('@@', ''),
        ('%08X' % glob) if glob else '-',
        ('%08X' % load) if isinstance(load, int) and load else '-',
        ('%08X' % rp) if isinstance(rp, int) and rp else '-'))
    if cls != '?':
        ok += 1

open(OUT_MD, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
print('写出', OUT_MD, '解析成功', ok, '项')
