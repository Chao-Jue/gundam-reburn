"""通用 xref：找所有指向 VA 的 call/jmp/jcc rel32 与 imm32。"""
import re
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

IMG = Path(r"D:\project\gundam-reburn\server\img_dump\main_GundamOnline_CHINA.exe")
BASE = 0x400000
MD = Cs(CS_ARCH_X86, CS_MODE_32)
img = IMG.read_bytes()

targets = [int(a, 0) for a in sys.argv[1:]]
if not targets:
    raise SystemExit("usage: _xref.py 0xVA [0xVA...]")

for va in targets:
    print(f"\n########## xref 0x{va:x} ##########")
    hits = []
    # imm32
    for m in re.finditer(re.escape(va.to_bytes(4, "little")), img):
        hits.append((m.start(), "imm32"))
    # rel32: E8/E9 and 0F 8x
    for o in range(len(img) - 6):
        b = img[o]
        if b in (0xE8, 0xE9):
            disp = int.from_bytes(img[o + 1:o + 5], "little", signed=True)
            if (BASE + o + 5 + disp) & 0xFFFFFFFF == va:
                hits.append((o, "call/jmp"))
        elif b == 0x0F and 0x80 <= img[o + 1] <= 0x8F:
            disp = int.from_bytes(img[o + 2:o + 6], "little", signed=True)
            if (BASE + o + 6 + disp) & 0xFFFFFFFF == va:
                hits.append((o, "jcc"))
    hits.sort()
    print(f"共 {len(hits)} 处")
    seen = set()
    for o, kind in hits:
        if o in seen:
            continue
        seen.add(o)
        print(f"\n--- {kind} 0x{BASE+o:x} ---")
        st = max(0, o - 24)
        for ins in MD.disasm(img[st:o + 12], BASE + st):
            print(f"  0x{ins.address:08x}  {ins.bytes.hex():<18} {ins.mnemonic:<7} {ins.op_str}")
