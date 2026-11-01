# -*- coding: utf-8 -*-
"""列出所有引用某个绝对全局地址的指令位置（a1 xx / 8b 0d xx / ff 15 xx 等）。"""
import sys, struct
from pathlib import Path
img = Path("D:/project/gundam-reburn/server/img_dump/main_GundamOnline_CHINA.exe").read_bytes()
B = 0x400000
g = int(sys.argv[1], 0)
imm = struct.pack("<I", g)
i = 0
out = []
while True:
    j = img.find(imm, i)
    if j < 0:
        break
    out.append(B + j)
    i = j + 1
print("0x%08X 被引用 %d 处" % (g, len(out)))
for va in out:
    off = va - B
    print("  0x%08X   前 6 字节: %s" % (va, img[off - 6:off].hex(" ")))
