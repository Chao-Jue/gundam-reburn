"""找出所有引用某个绝对地址（全局变量）的指令。"""
import re
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

IMG = Path(r"D:\project\gundam-reburn\server\img_dump\main_GundamOnline_CHINA.exe")
BASE = 0x400000
MD = Cs(CS_ARCH_X86, CS_MODE_32)
img = IMG.read_bytes()

addr = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x117D380
pat = addr.to_bytes(4, "little")

# 常见绝对寻址编码
encs = []
for modrm in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D):
    encs.append((bytes([0x8B, modrm]), "mov reg,[abs]"))
    encs.append((bytes([0x89, modrm]), "mov [abs],reg"))
encs += [
    (bytes([0xA1]), "mov eax,[abs]"),
    (bytes([0xA3]), "mov [abs],eax"),
    (bytes([0xFF, 0x35]), "push [abs]"),
    (bytes([0xFF, 0x05]), "inc [abs]"),
    (bytes([0x68]), "push imm"),
]

hits = []
for m in re.finditer(re.escape(pat), img):
    o = m.start()
    for k in range(1, 7):
        pre = img[o - k:o]
        for enc, kind in encs:
            if pre.endswith(enc):
                hits.append((o, o - len(enc), kind, enc))
                break
hits.sort(key=lambda h: h[0])

print(f"0x{addr:x} 的绝对引用共 {len(hits)} 处")
seen = set()
for o, start, kind, enc in hits:
    if start in seen:
        continue
    seen.add(start)
    va = BASE + start
    print(f"\n=== {kind} @ 0x{va:x} (enc {enc.hex()}) ===")
    st = max(0, start - 24)
    for ins in MD.disasm(img[st:o + 8], BASE + st):
        print(f"  0x{ins.address:08x}  {ins.bytes.hex():<20} {ins.mnemonic:<7} {ins.op_str}")
