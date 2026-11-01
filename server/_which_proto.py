# -*- coding: utf-8 -*-
"""取若干 vtable 的 +0x54 (on_message)，各自枚举 opcode 分发表，判断谁处理 0x5290。"""
import json, struct
from pathlib import Path
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

ROOT = Path(__file__).resolve().parent.parent
img = (ROOT/"server"/"img_dump"/"main_GundamOnline_CHINA.exe").read_bytes()
B = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)

def dword(va): return struct.unpack_from("<I", img, va-B)[0]

def enum_table(start, size=0x40000):
    """扫描 start..start+size 里的二分查找链，返回 {opcode: handler}"""
    tab, last = {}, None
    for ins in md.disasm(img[start-B:start-B+size], start):
        m, s = ins.mnemonic, ins.op_str
        if m in ("cmp", "sub") and s.startswith("eax,"):
            try: last = int(s.split(",")[1].strip(), 16)
            except Exception: last = None
        elif m == "je" and last is not None:
            if last < 0x10000:
                tab.setdefault(last, int(s, 16))
            last = None
        elif m in ("jg","jl","jle","jge","jne","jmp","nop"):
            continue
        else:
            last = None
    return tab

for name, vt in (("CGVOProtoLounge", 0xE14D04), ("proto@0x3BF0", 0xE1498C)):
    om = dword(vt + 0x54)
    err = dword(vt + 0x64)
    print(f"\n=== {name}  vtable=0x{vt:08X}  +0x54(on_message)=0x{om:08X}  +0x64(error)=0x{err:08X}")
    tab = enum_table(om)
    print(f"    分发表 {len(tab)} 条")
    for q in (0x5290, 0xE13A, 0x063E, 0xC43C, 0xF86A):
        print(f"      0x{q:04X}: {hex(tab[q]) if q in tab else '-'}")
    if 0x5290 in tab:
        print(f"    ★ 0x5290 由这个 proto 处理 -> handler 0x{tab[0x5290]:08X}")
