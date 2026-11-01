# -*- coding: utf-8 -*-
"""枚举 CGVOProtoLounge::on_message (0xAA2D50) 的 opcode 分发表。
二分查找链形态： cmp eax, imm32 / jg X / je Y  →  Y 就是该 opcode 的 handler。
"""
import sys, json
from pathlib import Path
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

ROOT = Path(__file__).resolve().parent.parent
IMG = ROOT / "server" / "img_dump" / "main_GundamOnline_CHINA.exe"
BASE = 0x400000
img = IMG.read_bytes()
md = Cs(CS_ARCH_X86, CS_MODE_32)

def off(va): return va - BASE

START = 0xAA2DD8
END   = 0xAD5E00          # 一直到统一收尾 0xAD5E15 之前

# 线性反汇编，收集 cmp eax,imm / je 目标
ins_list = []
for ins in md.disasm(img[off(START):off(END)], START):
    ins_list.append(ins)

cmps = {}      # opcode -> handler
last_cmp = None
for i, ins in enumerate(ins_list):
    if ins.mnemonic == "cmp" and ins.op_str.startswith("eax,"):
        try: last_cmp = int(ins.op_str.split(",")[1].strip(), 16)
        except: last_cmp = None
    elif ins.mnemonic == "je" and last_cmp is not None:
        cmps[last_cmp] = int(ins.op_str, 16)
        last_cmp = None
    elif ins.mnemonic in ("jg","jl","jle","jge","jne","jmp"):
        continue
    else:
        # 中间插入其他指令则作废
        if ins.mnemonic not in ("je","jg","jl","jle","jge","jne"):
            pass

# 只保留 <0x10000 的（u16 opcode）且目标在函数内
cand = {k:v for k,v in cmps.items() if k < 0x10000}
print(f"[*] 线性反汇编 {len(ins_list)} 条，命中 cmp-eax 常量 {len(cmps)} 个，u16 候选 {len(cand)} 个")
for k in sorted(cand):
    print(f"  0x{k:04X}  ->  0x{cand[k]:08X}")

print()
print("[?] 0xE13A 在表里吗:", "是" if 0xE13A in cand else "★ 否 ★")
print("[?] 0xE139 在表里吗:", "是" if 0xE139 in cand else "否")
json.dump({f"{k:04X}":f"{v:08X}" for k,v in sorted(cand.items())},
          open(ROOT/"server"/"lounge_dispatch_table.json","w"), indent=1)
