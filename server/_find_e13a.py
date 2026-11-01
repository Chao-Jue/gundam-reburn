# -*- coding: utf-8 -*-
"""在整个解包镜像里精确搜 0xE13A / 0xDFC2 作为立即数出现的所有位置。"""
from pathlib import Path
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

ROOT = Path(__file__).resolve().parent.parent
img = (ROOT/"server"/"img_dump"/"main_GundamOnline_CHINA.exe").read_bytes()
BASE = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)

# 立即数 0xE13A 的编码形式: 66 3d(ax) / 3d(eax) / 81 f8(eax) / 81 fe(esi) / 81 ff(edi) /
# 3c(?) etc. 统一做法: 搜字节 3a e1 00 00 前一个字节属于 cmp imm 指令族
PAT = b"\x3a\xe1\x00\x00"
hits = []
i = 0
while True:
    j = img.find(PAT, i)
    if j < 0: break
    hits.append(j); i = j+1
print(f"[*] '3a e1 00 00' 命中 {len(hits)} 处")
for h in hits:
    va = BASE + h
    pre = img[h-4:h+6]
    print(f"  0x{va:08X}  前4字节 {pre[:4].hex(' ')}  整段 {pre.hex(' ')}")

print()
# 直接验证: 有没有任何指令的操作数是 0xe13a
cnt = 0
for ins in md.disasm(img, BASE):
    if "0xe13a" in ins.op_str:
        print(f"  [insn] 0x{ins.address:08X}  {ins.mnemonic} {ins.op_str}")
        cnt += 1
        if cnt > 60: break
print(f"[*] 反汇编里操作数含 0xe13a 的指令 {cnt} 条")
