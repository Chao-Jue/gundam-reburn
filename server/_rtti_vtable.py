# -*- coding: utf-8 -*-
"""在 dump 出来的镜像上静态解析 RTTI → vtable。
用法: python server/_rtti_vtable.py "TIndexTable@UWEAPON_DATA"
"""
import re, struct, sys
import pefile

IMG = 'server/img_dump/main_GundamOnline_CHINA.exe'
data = open(IMG, 'rb').read()
pe = pefile.PE(IMG, fast_load=True)
BASE = pe.OPTIONAL_HEADER.ImageBase
SEC = [(s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData)
       for s in pe.sections]

def off2va(o):
    for va, sz, raw in SEC:
        if raw <= o < raw + sz:
            return BASE + va + (o - raw)
    return None

def va2off(va):
    rva = va - BASE
    for sva, sz, raw in SEC:
        if sva <= rva < sva + sz:
            return raw + (rva - sva)
    return None

def dword(va):
    o = va2off(va)
    return struct.unpack('<I', data[o:o+4])[0] if o is not None else None

def find_all(b, start=0):
    i = start
    while True:
        i = data.find(b, i)
        if i < 0:
            return
        yield i
        i += 1

def resolve(cls):
    pat = ('.?AV' + cls + '@@').encode('latin1')
    out = []
    for o in find_all(pat):
        name_va = off2va(o)
        if not name_va:
            continue
        td = name_va - 8                      # TypeDescriptor: vfptr, spare, name
        cols = [off2va(i) - 0xc for i in find_all(struct.pack('<I', td))]
        for col in cols:
            if not col or col < BASE:
                continue
            for i in find_all(struct.pack('<I', col)):
                vt = off2va(i) + 4
                out.append((cls, name_va, td, col, vt))
    return out

if __name__ == '__main__':
    for cls in sys.argv[1:]:
        rs = resolve(cls)
        print('==== %s: %d 个 vtable ====' % (cls, len(rs)))
        for c, nv, td, col, vt in rs:
            slots = [dword(vt + 4*k) for k in range(8)]
            print('  td=%08x col=%08x vtable=%08x' % (td, col, vt))
            print('    slots: ' + ', '.join('%08x' % s if s else '??' for s in slots))
