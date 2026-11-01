"""找 `mov rB,[rX+0x78]` 且 rB 刚由 `mov rB,[rY]` 载入（= 取 vtable 后再取槽）的点。"""
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

IMG = Path(r"D:\project\gundam-reburn\server\img_dump\main_GundamOnline_CHINA.exe")
BASE = 0x400000
MD = Cs(CS_ARCH_X86, CS_MODE_32)
img = IMG.read_bytes()

disp = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x78
lo = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x400000
hi = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x1200000

found = []
for o in range(lo - BASE, min(hi - BASE, len(img)) - 3):
    if img[o] != 0x8B:
        continue
    modrm = img[o + 1]
    if (modrm & 0xC0) != 0x40 or (modrm & 7) == 4:
        continue
    if img[o + 2] != disp:
        continue
    dst_reg = (modrm >> 3) & 7
    base_reg = modrm & 7
    # 回溯 20 字节内找 `mov dst_reg,[base_reg]`  (8b modrm mod=00 rm=base_reg reg=dst_reg)
    for back in range(2, 21):
        p = o - back
        if p < 0:
            break
        if img[p] != 0x8B:
            continue
        m2 = img[p + 1]
        if (m2 & 0xC0) != 0x00:
            continue
        if ((m2 >> 3) & 7) != base_reg:
            continue
        # 要求中间没有别的写 dst_reg 的指令：粗略忽略
        found.append((o, dst_reg, base_reg, p))
        break

print(f"候选 {len(found)} 处")
seen = set()
for o, dst, base, p in found:
    if o in seen:
        continue
    seen.add(o)
    print(f"\n=== 0x{BASE+o:x}  mov r{dst},[r{base}+{disp:#x}]  (vtable load @0x{BASE+p:x}) ===")
    st = max(0, p - 24)
    for ins in MD.disasm(img[st:o + 80], BASE + st):
        print(f"  0x{ins.address:08x}  {ins.bytes.hex():<20} {ins.mnemonic:<7} {ins.op_str}")
