#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""按 RVA 反汇编 GundamOnline_CHINA.exe 的任意区间。

用法:
    python tools/disasm_region.py 0x58ef85 0x200
    python tools/disasm_region.py 0x210000 0x100 --base 0x400000
    python tools/disasm_region.py 0x58f16b 0x60 --align        # 自动找对齐起点

说明:
- 目标 exe 外层是 Themida，但 main 节里 0x5xxxxx / 0x21xxxx 这一段是明文代码，
  可以直接按 RVA 反汇编。
- frida 报告的是 RVA (模块基址 0x400000)，所以本工具默认 base=0x400000，
  打印时同时给 VA(0x4xxxxx) 和 RVA。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import capstone
import pefile

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "launcher" / "gundam" / "机动战士敢达Online" / "GundamOnline" / "GundamOnline_CHINA.exe"

IMAGE_BASE_DEFAULT = 0x400000


def load_raw() -> bytes:
    return EXE.read_bytes()


def rva_to_off(pe: pefile.PE, rva: int) -> int:
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    raise ValueError(f"RVA 0x{rva:x} 不在任何节里")


def section_of(pe: pefile.PE, rva: int) -> str:
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.Name.rstrip(b"\x00").decode("latin1")
    return "?"


def fmt_bytes(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rva", help="起始 RVA，如 0x58ef85（可带或不带 0x）")
    ap.add_argument("length", nargs="?", default="0x200", help="字节数（默认 0x200）")
    ap.add_argument("--base", default=hex(IMAGE_BASE_DEFAULT), help="镜像基址，默认 0x400000")
    ap.add_argument("--align", action="store_true",
                    help="从给定 RVA 往前最多扫 64 字节，找使线性反汇编恰好命中指定 RVA 的起点")
    ap.add_argument("--no-bytes", action="store_true", help="不打印原始字节列")
    args = ap.parse_args()

    rva = int(args.rva, 0)
    length = int(args.length, 0)
    base = int(args.base, 0)

    data = load_raw()
    pe = pefile.PE(data=data, fast_load=True)
    # 若 exe 的 ImageBase 与传入不同，以传入为准（hex 里看到的就是 0x400000）
    off = rva_to_off(pe, rva)
    sec = section_of(pe, rva)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True

    start_rva = rva
    if args.align:
        # 找一个起点，使得从它开始线性反汇编时，rva 恰好落在一条指令的边界上
        blob = data[off - 64: off + 16]
        for back in range(0, 65):
            s_off = 64 - back
            found = False
            for ins in md.disasm(blob[s_off:], base + rva - back):
                if ins.address == base + rva:
                    found = True
                    break
                if ins.address > base + rva:
                    break
            if found:
                start_rva = rva - back
                print(f"[align] 找到对齐起点 RVA 0x{start_rva:x}（回退 {back} 字节）")
                break
        else:
            print("[align] 未找到，使用原 RVA", file=sys.stderr)

    off = rva_to_off(pe, start_rva)
    blob = data[off: off + length]

    print(f"文件: {EXE.name}  节: {sec}  ImageBase=0x{base:x}")
    print(f"RVA 0x{start_rva:x} .. 0x{start_rva + len(blob):x}   VA 0x{base + start_rva:x}")
    print("-" * 96)

    notes = {
        0x1162058: "要求分辨率配置对象指针",
        0xCAA448: "GetSystemMetrics 导入指针",
    }
    for ins in md.disasm(blob, base + start_rva):
        rva_i = ins.address - base
        line = f"RVA {rva_i:08x}  VA {ins.address:08x}  {ins.mnemonic:<7}{ins.op_str}"
        if not args.no_bytes:
            line = f"{fmt_bytes(ins.bytes):<26} {line}"
        print(line)
        # 顺手把内存操作数里的绝对地址翻译一下
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                tgt = op.mem.disp
                if tgt in notes:
                    print(f"{'':>26}   ; -> [{tgt:#x}] {notes[tgt]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
