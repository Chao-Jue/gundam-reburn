"""扫描全镜像里 call/jmp dword ptr [reg+0x78] 的点，并对每个命中点做局部反汇编。"""
import re
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

IMG = Path(r"D:\project\gundam-reburn\server\img_dump\main_GundamOnline_CHINA.exe")
BASE = 0x400000
MD = Cs(CS_ARCH_X86, CS_MODE_32)

img = IMG.read_bytes()

# call [reg+disp8]  : FF /2  modrm mod=01 rm=reg disp8
# ff 50 78 = call [eax+78]; ff 51 78 = ecx; ff 52 78 = edx; ff 53 78 = ebx
# ff 55 78 = ebp; ff 56 78 = esi; ff 57 78 = edi
pats = {}
for op in (0x10, 0x11, 0x12, 0x13, 0x15, 0x16, 0x17):
    pats[bytes([0xFF, op, 0x78])] = "call"
    pats[bytes([0xFF, op | 0x20, 0x78])] = "jmp"
# ff 90 78 00 00 00 = call [eax+0x78] (disp32)
for op in (0x90, 0x91, 0x92, 0x93, 0x95, 0x96, 0x97):
    pats[bytes([0xFF, op]) + (0x78).to_bytes(4, "little")] = "call32"
    pats[bytes([0xFF, op | 0x20]) + (0x78).to_bytes(4, "little")] = "jmp32"

hits = []
for pat, kind in pats.items():
    for m in re.finditer(re.escape(pat), img):
        hits.append((m.start(), kind, pat))
hits.sort()

print(f"命中 {len(hits)} 处")
for o, kind, pat in hits:
    va = BASE + o
    print(f"\n=== {kind} {pat.hex()} @ 0x{va:x} ===")
    start = max(0, o - 48)
    for ins in MD.disasm(img[start:o + 16], BASE + start):
        mark = " <<<" if ins.address == va else ""
        print(f"  0x{ins.address:08x}  {ins.bytes.hex():<20} {ins.mnemonic:<7} {ins.op_str}{mark}")
