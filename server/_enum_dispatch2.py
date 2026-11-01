# -*- coding: utf-8 -*-
"""补全分发表：除 cmp eax,imm 外，编译器还会用 sub eax,imm / je 的形式（线性尾段）。
两者合并才是完整表。"""
import json, struct
from pathlib import Path
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

ROOT = Path(__file__).resolve().parent.parent
IMG = ROOT / "server" / "img_dump" / "main_GundamOnline_CHINA.exe"
BASE, START, END = 0x400000, 0xAA2DD8, 0xAD5E00
img = IMG.read_bytes()
md = Cs(CS_ARCH_X86, CS_MODE_32)

table = {int(k, 16): int(v, 16) for k, v in
         json.load(open(ROOT / "server" / "lounge_dispatch_table.json")).items()}
before = len(table)

# sub 形式：逐条线性反汇编，遇到 sub eax,imm 后紧跟 je 就记账
last = None
for ins in md.disasm(img[START-BASE:END-BASE], START):
    if ins.mnemonic == "sub" and ins.op_str.startswith("eax,"):
        try:
            last = int(ins.op_str.split(",")[1].strip(), 16)
        except Exception:
            last = None
    elif ins.mnemonic == "je" and last is not None:
        if last < 0x10000:
            table.setdefault(last, int(ins.op_str, 16))
            print(f"  [sub] 0x{last:04X} -> 0x{int(ins.op_str,16):08X}")
        last = None
    elif ins.mnemonic in ("jg", "jl", "jle", "jge", "jne", "jmp", "nop"):
        continue
    else:
        last = None

print(f"[*] cmp 表 {before} 条 -> 补全后 {len(table)} 条（新增 {len(table)-before}）")
json.dump({f"{k:04X}": f"{v:08X}" for k, v in sorted(table.items())},
          open(ROOT / "server" / "lounge_dispatch_table.json", "w"), indent=1)
for q in (0x5290, 0xE13A, 0x60CD, 0xF86A):
    print(f"  ? 0x{q:04X}: {hex(table[q]) if q in table else '不在表里'}")
