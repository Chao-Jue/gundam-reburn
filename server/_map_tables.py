# -*- coding: utf-8 -*-
"""解析 0x544E3C 的文件序号跳转表，提取每个 case 用的表对象全局。"""
import struct, re, pefile

IMG = 'server/img_dump/main_GundamOnline_CHINA.exe'
data = open(IMG, 'rb').read()
pe = pefile.PE(IMG, fast_load=True); BASE = pe.OPTIONAL_HEADER.ImageBase
SEC = [(s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData) for s in pe.sections]

def va2off(va):
    rva = va - BASE
    for sva, sz, raw in SEC:
        if sva <= rva < sva + sz:
            return raw + (rva - sva)

def dw(va):
    o = va2off(va)
    return struct.unpack('<I', data[o:o+4])[0] if o is not None else None

TBL = 0x544E3C
N = 0x47
rows = []
for i in range(N):
    ent = dw(TBL + 4*i)
    if not ent:
        continue
    code = data[va2off(ent):va2off(ent)+0x50]
    # mov ecx, dword ptr [0x........]  => 8b 0d xx xx xx xx
    glob = None
    m = re.search(rb'\x8b\x0d(....)', code, re.S)
    if m:
        glob = struct.unpack('<I', m.group(1))[0]
    # 直接 call 的目标
    calls = [struct.unpack('<I', mm.group(1))[0] for mm in re.finditer(rb'\xe8(....)', code, re.S)]
    calls = [c + 0 for c in calls]
    rows.append((i, ent, glob, calls[:4]))

print('idx  case       global      codes')
for i, ent, glob, calls in rows:
    print('%3d  %08X   %s   %s' % (i, ent, ('%08X' % glob) if glob else '   --   ',
          ' '.join('%08X' % c for c in calls)))
