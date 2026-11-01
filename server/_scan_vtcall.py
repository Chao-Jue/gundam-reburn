"""找 `mov rA,[rB+disp]` 且后续同寄存器被 call 的点。"""
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

IMG = Path(r"D:\project\gundam-reburn\server\img_dump\main_GundamOnline_CHINA.exe")
BASE = 0x400000
MD = Cs(CS_ARCH_X86, CS_MODE_32)
img = IMG.read_bytes()

disp = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x20
lo = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x400000
hi = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x1200000

cands = []
for o in range(lo - BASE, min(hi - BASE, len(img)) - 3):
    if img[o] != 0x8B:
        continue
    modrm = img[o + 1]
    if (modrm & 0xC0) != 0x40 or (modrm & 7) == 4:
        continue
    if img[o + 2] != disp:
        continue
    reg = (modrm >> 3) & 7
    rm = modrm & 7
    tail = img[o + 3:o + 3 + 64]
    callpat = bytes([0xFF, 0xD0 | reg])
    if callpat in tail:
        cands.append((o, reg, rm))

print(f"disp=0x{disp:x} 候选 {len(cands)} 处")
for o, reg, rm in cands:
    print(f"\n=== 0x{BASE+o:x}  mov r{reg},[r{rm}+{disp:#x}] -> call r{reg} ===")
    st = max(0, o - 32)
    for ins in MD.disasm(img[st:o + 60], BASE + st):
        print(f"  0x{ins.address:08x}  {ins.bytes.hex():<20} {ins.mnemonic:<7} {ins.op_str}")
