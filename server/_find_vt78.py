# -*- coding: utf-8 -*-
"""搜 `call dword ptr [reg+0x78]`（ff 5x 78）的所有位置。"""
from pathlib import Path
img = Path("D:/project/gundam-reburn/server/img_dump/main_GundamOnline_CHINA.exe").read_bytes()
B = 0x400000
hits = []
for reg in range(8):                 # ff 50..ff 57 78
    pat = bytes([0xFF, 0x50 + reg, 0x78])
    i = 0
    while True:
        j = img.find(pat, i)
        if j < 0:
            break
        hits.append((B + j, reg))
        i = j + 1
hits.sort()
print("命中", len(hits))
for va, reg in hits:
    print("  0x%08X   call [%s+0x78]" % (va, "eax ecx edx ebx esp ebp esi edi".split()[reg]))
