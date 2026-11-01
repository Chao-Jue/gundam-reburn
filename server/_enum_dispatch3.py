"""递归解析 CGVOProtoLounge::on_message 的二分查找树，输出 opcode -> handler。"""
import json
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

IMG = Path(r"D:\project\gundam-reburn\server\img_dump\main_GundamOnline_CHINA.exe")
BASE = 0x400000
MD = Cs(CS_ARCH_X86, CS_MODE_32)
img = IMG.read_bytes()
END = 0xAD5E15          # 统一收尾

def dis1(va):
    for ins in MD.disasm(img[va - BASE:va - BASE + 16], va):
        return ins
    return None

tree = {}
visited = set()
notes = []

def walk(va, depth=0):
    if va in visited:
        notes.append(f"loop at 0x{va:x}")
        return
    visited.add(va)
    ins = dis1(va)
    if ins is None:
        notes.append(f"bad va 0x{va:x}")
        return
    m = ins.mnemonic
    ops = ins.op_str
    # 形态1: cmp eax, imm
    if m == "cmp" and ops.startswith("eax,"):
        imm = int(ops.split(",")[1].strip(), 0)
        j1 = dis1(va + ins.size)
        if j1 is None:
            return
        j2 = dis1(j1.address + j1.size)
        pairs = [(j1.mnemonic, j1.op_str), (j2.mnemonic, j2.op_str)] if j2 else [(j1.mnemonic, j1.op_str)]
        tgt_big = tgt_eq = None
        for mm, oo in pairs:
            if not oo.startswith("0x"):
                continue
            t = int(oo, 16)
            if mm in ("jg", "ja"):
                tgt_big = t
            elif mm in ("je", "jz"):
                tgt_eq = t
            elif mm in ("ge", "jge"):
                tgt_big = t          # 近似
            elif mm in ("l", "jl", "le", "jle"):
                notes.append(f"0x{va:x}: {mm} {oo}")
        if tgt_eq is not None:
            tree[imm] = tgt_eq
        # 两条跳转之后 = 小于分支
        nxt = j2.address + j2.size if j2 else j1.address + j1.size
        if tgt_big is not None:
            walk(tgt_big, depth + 1)
        walk(nxt, depth + 1)
        return
    # 形态2: sub eax, imm ; je
    if m == "sub" and ops.startswith("eax,"):
        imm = int(ops.split(",")[1].strip(), 0)
        j1 = dis1(va + ins.size)
        if j1 and j1.mnemonic in ("je", "jz") and j1.op_str.startswith("0x"):
            tree[imm] = int(j1.op_str, 16)
            walk(j1.address + j1.size, depth + 1)
            return
        notes.append(f"0x{va:x}: sub eax,{imm} -> {j1.mnemonic if j1 else '?'} {j1.op_str if j1 else ''}")
        return
    notes.append(f"0x{va:x}: {m} {ops}")

walk(0xAA2DDD)
print(f"解析出 {len(tree)} 个 opcode，访问 {len(visited)} 个节点")
for n in notes[:40]:
    print("  NOTE", n)

for probe in (0x5290, 0xE13A, 0xF86A, 0xE139):
    print(f"0x{probe:04X} -> {hex(tree[probe]) if probe in tree else '不在表里'}")

json.dump({f"{k:04X}": f"{v:08X}" for k, v in sorted(tree.items())},
          open(r"D:\project\gundam-reburn\server\lounge_dispatch_table2.json", "w"), indent=1)
