# -*- coding: utf-8 -*-
"""找 `mov r,[vt+0x78]` 之后 30 字节内出现 `ff d0`(call eax)/`ff d1`/`ff d2`/`ff d3` 的位置。"""
from pathlib import Path
img = Path("D:/project/gundam-reburn/server/img_dump/main_GundamOnline_CHINA.exe").read_bytes()
B = 0x400000
cands = []
for p in (b"\x8b\x40\x78", b"\x8b\x41\x78", b"\x8b\x42\x78", b"\x8b\x43\x78",
          b"\x8b\x45\x78", b"\x8b\x46\x78", b"\x8b\x47\x78"):
    i = 0
    while True:
        j = img.find(p, i)
        if j < 0:
            break
        window = img[j:j + 40]
        if b"\xff\xd0" in window or b"\xff\xd1" in window or b"\xff\xd2" in window or b"\xff\xd3" in window:
            cands.append((B + j, p.hex(" ")))
        i = j + 1
cands.sort()
print("候选", len(cands))
for va, h in cands:
    d = va - B
    print("  0x%08X  %s   ctx=%s" % (va, h, img[d - 8:d + 12].hex(" ")))
