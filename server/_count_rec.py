"""独立核算 0xA956F0（parse_pilot_record）的线上消费字节数。

不靠"读代码印象"，而是：反汇编整段，统计
  ① 每个 helper 调用（a5a310=4 / a5a330=2 / a5a360=1 / a5de30=avatar 18）
  ② 显式 `add dword ptr [esi], imm`（含 esi 别名）
  ③ 内联 25 字节拷贝循环（cmp reg,0x19）
再做合计。
"""
import re
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

IMG = Path(r"D:\project\gundam-reburn\server\img_dump\main_GundamOnline_CHINA.exe")
BASE = 0x400000
MD = Cs(CS_ARCH_X86, CS_MODE_32)
img = IMG.read_bytes()

START = 0xA956F0
END = 0xA95C40

WIDTH = {
    0xA5A310: ("a5a310 u32", 4),
    0xA5A330: ("a5a330 u16", 2),
    0xA5A360: ("a5a360 u8", 1),
    0xA5DE30: ("a5de30 avatar", 18),
}

counts = {}
adds = []
loops25 = []
other_calls = []

calls = {}
for ins in MD.disasm(img[START - BASE:END - BASE], START):
    if ins.mnemonic == "call":
        try:
            t = int(ins.op_str, 16)
        except ValueError:
            other_calls.append((ins.address, ins.op_str))
            continue
        if t in WIDTH:
            counts[t] = counts.get(t, 0) + 1
        else:
            calls[t] = calls.get(t, 0) + 1
    elif ins.mnemonic == "add" and "dword ptr [esi]" in ins.op_str and "," in ins.op_str:
        try:
            n = int(ins.op_str.split(",")[1].strip(), 0)
        except ValueError:
            n = None
        adds.append((ins.address, ins.op_str, n))
    elif ins.mnemonic == "cmp" and ins.op_str.startswith("eax,0x19"):
        loops25.append(ins.address)

total = 0
detail = []
for va, (name, w) in WIDTH.items():
    c = counts.get(va, 0)
    if c:
        total += c * w
        detail.append("%-16s x%-3d = %4d" % (name, c, c * w))
for va, ops, n in adds:
    if n:
        total += n
        detail.append("add [esi],%-4s x1  = %4d   @0x%x" % (n, n, va))
detail.append("inline25        x%-3d = %4d" % (len(loops25), len(loops25) * 25))
total += len(loops25) * 25

print("=== 0xA956F0 消费明细 ===")
for d in detail:
    print("  " + d)
print("  ------------------------------")
print("  合计 = %d 字节" % total)
print()
print("其它 call 目标：")
for t, c in sorted(calls.items()):
    print("  0x%08X x%d" % (t, c))
