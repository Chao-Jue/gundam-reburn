# -*- coding: utf-8 -*-
"""搜 `mov reg,[reg2+0x78]`（8b / 01 r r r / 78）与 `jmp [reg+0x78]`（ff 6x 78）。"""
from pathlib import Path
img = Path("D:/project/gundam-reburn/server/img_dump/main_GundamOnline_CHINA.exe").read_bytes()
B = 0x400000
hits = []
i = 0
while True:
    j = img.find(b"\x8b", i)
    if j < 0 or j + 3 > len(img):
        break
    modrm = img[j + 1]
    if img[j + 2] == 0x78 and (modrm & 0xC7) == 0x40:      # mod=01, rm 任意, disp8=0x78
        hits.append((B + j, "mov", modrm))
    i = j + 1
for reg in range(8):
    pat = bytes([0xFF, 0x60 + reg, 0x78])
    k = 0
    while True:
        p = img.find(pat, k)
        if p < 0:
            break
        hits.append((B + p, "jmp", reg))
        k = p + 1
hits.sort()
print("命中", len(hits))
for h in hits:
    print("  0x%08X  %s  modrm/reg=0x%02X" % (h[0], h[1], h[2]))
