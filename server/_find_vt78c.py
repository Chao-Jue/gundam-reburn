# -*- coding: utf-8 -*-
"""只找 on_message 区域（0xAA0000-0xAE0000）里 `mov eax,[reg+0x78]` 的形态。"""
from pathlib import Path
img = Path("D:/project/gundam-reburn/server/img_dump/main_GundamOnline_CHINA.exe").read_bytes()
B = 0x400000
LO, HI = 0xAA0000, 0xAE0000
pats = [b"\x8b\x40\x78", b"\x8b\x41\x78", b"\x8b\x42\x78", b"\x8b\x43\x78",
        b"\x8b\x45\x78", b"\x8b\x46\x78", b"\x8b\x47\x78"]
for p in pats:
    i = 0
    while True:
        j = img.find(p, i)
        if j < 0:
            break
        va = B + j
        if LO + B - B <= va - B + B <= HI:      # 只按 VA-B 判断
            pass
        off = j
        if LO <= off <= HI:
            print("  0x%08X  %s" % (va, p.hex(" ")))
        i = j + 1
print("done")
