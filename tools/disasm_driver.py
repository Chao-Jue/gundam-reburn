# -*- coding: utf-8 -*-
"""
反汇编 CPS_extracted.sys（x64 内核驱动），定位 IOCTL 分发与 0x222055 的读写语义。

用法：
    python tools/disasm_driver.py --scan                 # 扫所有 IOCTL 常量出现的位置（文件偏移 / RVA / 所在节）
    python tools/disasm_driver.py --at 0x1234 [--n 60]   # 从 RVA 起反汇编 n 条
    python tools/disasm_driver.py --xref 0x222055        # 反汇编引用该常量的前后代码
"""
import argparse
import struct
import sys
from pathlib import Path

import capstone
import pefile

ROOT = Path(__file__).resolve().parent.parent
DRV = ROOT / "server" / "CPS_extracted.sys"

# 运行期实测见过的 IOCTL
CODES = [
    0x222015, 0x22202D, 0x222035, 0x22204E, 0x222045,
    0x222055, 0x222059, 0x22207C, 0x222029,
    0x470813, 0xB01A8, 0x47081B, 0xB0193,
]


def load():
    pe = pefile.PE(str(DRV), fast_load=True)
    data = DRV.read_bytes()
    return pe, data


def rva_to_off(pe, rva):
    for s in pe.sections:
        vsz = max(s.Misc_VirtualSize, s.SizeOfRawData)
        if s.VirtualAddress <= rva < s.VirtualAddress + vsz:
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None


def off_to_rva(pe, off):
    for s in pe.sections:
        if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData:
            return s.VirtualAddress + (off - s.PointerToRawData)
    return None


def sec_name(pe, rva):
    for s in pe.sections:
        vsz = max(s.Misc_VirtualSize, s.SizeOfRawData)
        if s.VirtualAddress <= rva < s.VirtualAddress + vsz:
            return s.Name.rstrip(b"\x00").decode("ascii", "replace")
    return "?"


def scan(data, pe, needle4=None):
    hits = []
    for c in (CODES if needle4 is None else [needle4]):
        pat = struct.pack("<I", c)
        start = 0
        while True:
            i = data.find(pat, start)
            if i < 0:
                break
            rva = off_to_rva(pe, i)
            hits.append((c, i, rva, sec_name(pe, rva) if rva is not None else "?"))
            start = i + 1
    return hits


def disasm(pe, data, rva, n=60, imagebase=None):
    ib = imagebase if imagebase is not None else pe.OPTIONAL_HEADER.ImageBase
    off = rva_to_off(pe, rva)
    if off is None:
        print(f"RVA {rva:#x} 不在任何节里")
        return
    code = data[off: off + n * 15]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    print(f"--- RVA {rva:#x} ({sec_name(pe, rva)}) VA {ib + rva:#x} ---")
    for i, ins in enumerate(md.disasm(code, ib + rva)):
        mark = ""
        for c in CODES:
            if f"{c:#x}" in ins.op_str:
                mark = f"   <== IOCTL {c:#x}"
        print(f"  {rva + (ins.address - ib - rva):#08x}  {ins.bytes.hex():<24} {ins.mnemonic:<8} {ins.op_str}{mark}")
        if i + 1 >= n:
            break


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", action="store_true")
    ap.add_argument("--at", type=lambda x: int(x, 0))
    ap.add_argument("--n", type=int, default=60)
    ap.add_argument("--xref", type=lambda x: int(x, 0))
    args = ap.parse_args()

    pe, data = load()
    print(f"驱动 {DRV.name}  {len(data)} 字节  ImageBase={pe.OPTIONAL_HEADER.ImageBase:#x}")
    for s in pe.sections:
        print(f"  {s.Name.rstrip(chr(0).encode()).decode('ascii','replace'):<10} "
              f"VA={s.VirtualAddress:#010x} VSz={s.Misc_VirtualSize:#08x} Raw={s.SizeOfRawData:#08x}")

    if args.scan or (args.at is None and args.xref is None):
        print("\n=== IOCTL 常量引用点 ===")
        hits = scan(data, pe)
        # 按 RVa 排序
        hits.sort(key=lambda h: (h[3], h[0]))
        for c, off, rva, sec in hits:
            kind = "代码" if sec in (".text", "") or sec.startswith(".") else sec
            print(f"  {c:#010x}  文件偏移 {off:#08x}  RVA {(rva if rva is not None else -1):#010x}  节 {sec}")

    if args.xref is not None:
        for c, off, rva, sec in scan(data, pe, args.xref):
            print()
            back = max(0, rva - 0x60)
            disasm(pe, data, back, n=48)

    if args.at is not None:
        disasm(pe, data, args.at, n=args.n)


if __name__ == "__main__":
    main()
