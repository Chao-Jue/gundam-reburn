# -*- coding: utf-8 -*-
"""解析解包镜像的导入表，找 OutputDebugString 的 IAT 槽，再数代码里对它有多少次 call/jmp。
RVA == 文件偏移（镜像是基址 0x400000 的平坦镜像）。"""
import struct
from pathlib import Path

BASE = 0x400000
img = Path("D:/project/gundam-reburn/server/img_dump/main_GundamOnline_CHINA.exe").read_bytes()

e_lfanew = struct.unpack_from("<I", img, 0x3C)[0]
assert img[e_lfanew:e_lfanew+4] == b"PE\0\0"
coff = e_lfanew + 4
nsec = struct.unpack_from("<H", img, coff+2)[0]
opt_size = struct.unpack_from("<H", img, coff+16)[0]
opt = coff + 20
magic = struct.unpack_from("<H", img, opt)[0]
print("PE32" if magic == 0x10b else "PE32+", "sections", nsec)
dd = opt + (96 if magic == 0x10b else 112)
imp_rva, imp_size = struct.unpack_from("<II", img, dd + 8)   # data dir[1] = import
print(f"import dir rva=0x{imp_rva:x} size={imp_size}")

names = {}
i = 0
while True:
    oft, ts, fwd, name_rva, ft = struct.unpack_from("<IIIII", img, imp_rva + i*20)
    if name_rva == 0:
        break
    dll = img[name_rva:img.index(b"\0", name_rva)].decode("mbcs", "replace")
    thunk_rva = oft or ft
    k = 0
    while True:
        v = struct.unpack_from("<I", img, thunk_rva + k*4)[0]
        if v == 0:
            break
        iat_va = BASE + ft + k*4
        if not (v & 0x80000000):
            nm = img[v+2:img.index(b"\0", v+2)].decode("ascii", "replace")
            names.setdefault(nm, []).append((dll, iat_va))
        k += 1
    i += 1

hit = {k: v for k, v in names.items() if "DebugString" in k}
print("导入里的 DebugString 相关:", hit)

for nm, lst in hit.items():
    for dll, iat in lst:
        pat = b"\xff\x15" + struct.pack("<I", iat)     # call dword ptr [iat]
        pat2 = b"\xff\x25" + struct.pack("<I", iat)    # jmp  dword ptr [iat]
        sites, j = [], 0
        while True:
            p = img.find(pat, j)
            if p < 0:
                break
            sites.append(BASE + p); j = p + 1
        j = 0
        while True:
            p = img.find(pat2, j)
            if p < 0:
                break
            sites.append(BASE + p); j = p + 1
        print(f"{nm} @ {dll} IAT=0x{iat:08X}  代码引用 {len(sites)} 处: "
              + ", ".join(f"0x{a:08X}" for a in sites[:12]))
