# -*- coding: utf-8 -*-
"""列出 [s,e) 范围内的所有 call 目标。用法: python server/_calls_in.py 0x544F60 0x545600"""
import sys
from pathlib import Path
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

img = Path("D:/project/gundam-reburn/server/img_dump/main_GundamOnline_CHINA.exe").read_bytes()
B = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)
s, e = int(sys.argv[1], 0), int(sys.argv[2], 0)
n = 0
for ins in md.disasm(img[s - B: e - B], s):
    if ins.mnemonic == "call":
        print("  0x%08X  call %s" % (ins.address, ins.op_str))
        n += 1
    if ins.mnemonic in ("ret",) and ins.op_str.startswith("0x"):
        pass
print("total", n)
