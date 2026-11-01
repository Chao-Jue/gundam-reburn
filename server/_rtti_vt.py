# -*- coding: utf-8 -*-
"""给一个 TypeDescriptor VA，解出 vtable（COL 引用点 +4）。"""
import struct, sys
from pathlib import Path

img = Path("D:/project/gundam-reburn/server/img_dump/main_GundamOnline_CHINA.exe").read_bytes()
B = 0x400000

def resolve(td):
    col = struct.unpack_from("<I", img, td - B - 8)[0]
    print(f"TD 0x{td:08X}  COL 0x{col:08X}")
    pat = struct.pack("<I", col)
    i, out = 0, []
    while True:
        j = img.find(pat, i)
        if j < 0:
            break
        vt = B + j + 4
        slots = [struct.unpack_from("<I", img, vt - B + k * 4)[0] for k in range(6)]
        out.append((B + j, vt, slots))
        i = j + 1
    return out

if __name__ == "__main__":
    tds = [int(x, 0) for x in (sys.argv[1:] or ["0xC84528"])]
    for td in tds:
        for ref, vt, slots in resolve(td):
            print(f"  ref@0x{ref:08X}  vtable=0x{vt:08X}  "
                  + " ".join(f"v{k}=0x{s:08X}" for k, s in enumerate(slots)))
