"""扫描 call/jmp dword ptr [reg+disp8] （指定 disp），打印上下文。"""
import re
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

IMG = Path(r"D:\project\gundam-reburn\server\img_dump\main_GundamOnline_CHINA.exe")
BASE = 0x400000
MD = Cs(CS_ARCH_X86, CS_MODE_32)
img = IMG.read_bytes()

disp = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x20
lo = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0xB00000
hi = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0xC00000

pats = []
for modrm in range(0x40, 0x80):
    if (modrm & 7) == 4:
        continue
    pats.append(bytes([0xFF, modrm, disp]))
    pats.append(bytes([0xFF, modrm | 0x20, disp]))

hits = []
for pat in pats:
    for m in re.finditer(re.escape(pat), img):
        o = m.start()
        if lo - BASE <= o < hi - BASE:
            hits.append((o, pat.hex()))
hits.sort()

print(f"disp=0x{disp:x} 命中 {len(hits)} 处")
for o, hexpat in hits:
    va = BASE + o
    print(f"\n=== {hexpat} @ 0x{va:x} ===")
    st = max(0, o - 40)
    for ins in MD.disasm(img[st:o + 12], BASE + st):
        print(f"  0x{ins.address:08x}  {ins.bytes.hex():<20} {ins.mnemonic:<7} {ins.op_str}")
