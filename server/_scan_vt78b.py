"""找 `mov reg,[reg+0x78]` 且后面紧跟 `call reg` 的点（vt+0x78 调用）。"""
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

IMG = Path(r"D:\project\gundam-reburn\server\img_dump\main_GundamOnline_CHINA.exe")
BASE = 0x400000
MD = Cs(CS_ARCH_X86, CS_MODE_32)
img = IMG.read_bytes()

lo = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x900000
hi = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0xC00000

cands = []
for o in range(lo - BASE, min(hi - BASE, len(img)) - 3):
    b0, b1, b2 = img[o], img[o + 1], img[o + 2]
    if b0 != 0x8B:
        continue
    modrm = b1
    if (modrm & 0xC0) != 0x40:      # mod=01 disp8
        continue
    if img[o + 2] != 0x78:          # disp8 = 0x78
        continue
    reg = (modrm >> 3) & 7
    rm = modrm & 7
    if rm == 4:                     # SIB, not what we want
        continue
    # 看后面 48 字节里有没有 call reg (ff /2, mod=11) 或 jmp
    tail = img[o + 3:o + 3 + 48]
    callpat = bytes([0xFF, 0xD0 | reg])
    if callpat in tail or bytes([0xFF, 0xE0 | reg]) in tail:
        cands.append((o, reg, rm))

print(f"候选 {len(cands)} 处")
for o, reg, rm in cands:
    va = BASE + o
    print(f"\n=== 0x{va:x}  mov r{reg},[r{rm}+0x78] ===")
    st = max(0, o - 16)
    for ins in MD.disasm(img[st:o + 40], BASE + st):
        print(f"  0x{ins.address:08x}  {ins.bytes.hex():<20} {ins.mnemonic:<7} {ins.op_str}")
