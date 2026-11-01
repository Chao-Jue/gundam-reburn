#!/usr/bin/env python
"""在 dump 出来的客户端镜像上做静态反汇编（壳已解开，代码是真的）。

用法:
  python tools/dis_img.py --va 0x9cc590 --n 40          # 反汇编 40 条
  python tools/dis_img.py --va 0x9cc590 --prologue      # 从函数头开始（自动回溯）
  python tools/dis_img.py --va 0x9cc590 --callers       # 找谁 call/引用了这个地址
  python tools/dis_img.py --str "authsv"                # 在镜像里找字符串
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

ROOT = Path(__file__).resolve().parent.parent
IMG = ROOT / "server" / "img_dump" / "main_GundamOnline_CHINA.exe"
BASE = 0x400000

MD = Cs(CS_ARCH_X86, CS_MODE_32)


def load() -> bytes:
    if not IMG.exists():
        raise SystemExit(f"[!] 没有镜像：{IMG}\n    先跑 tools/run_hooked.py --scan-rtti N --dump-image")
    return IMG.read_bytes()


def off(va: int, img: bytes) -> int:
    o = va - BASE
    if o < 0 or o >= len(img):
        raise SystemExit(f"[!] VA 0x{va:x} 超出镜像范围（0x{BASE:x}..0x{BASE+len(img):x}）")
    return o


def find_prologue(img: bytes, va: int, limit: int = 0x400) -> int:
    """从 va 往前找函数头：`cc` 填充之后的第一条指令。"""
    o = off(va, img)
    start = max(0, o - limit)
    i = o
    while i > start:
        i -= 1
        if img[i] == 0xCC and img[i - 1] == 0xCC:
            return BASE + i + 1
    return va


def dis(img: bytes, va: int, n: int) -> None:
    o = off(va, img)
    c = 0
    for ins in MD.disasm(img[o:o + n * 8], va):
        print(f"  0x{ins.address:08x}  {ins.bytes.hex():<18} {ins.mnemonic:<8} {ins.op_str}")
        c += 1
        if c >= n:
            break


def callers(img: bytes, va: int) -> None:
    """找引用点：① 直接填了这个地址的 imm32；② `call rel32` / `jmp rel32` 指向它。"""
    pat = va.to_bytes(4, "little")
    hits = [("imm32", m.start()) for m in re.finditer(re.escape(pat), img)]
    # call/jmp rel32：E8/E9 后面 4 字节是有符号位移，目标 = 指令尾 + disp
    for o in range(len(img) - 5):
        if img[o] in (0xE8, 0xE9):
            disp = int.from_bytes(img[o + 1:o + 5], "little", signed=True)
            if (BASE + o + 5 + disp) & 0xFFFFFFFF == va:
                hits.append(("call/jmp", o))
    hits.sort(key=lambda x: x[1])
    print(f"引用 0x{va:x} 的位置共 {len(hits)} 处")
    for kind, h in hits[:12]:
        print(f"\n--- {kind} 引用 0x{BASE+h:x} ---")
        dis(img, BASE + max(0, h - 40), 16)


def main(argv: list[str]) -> int:
    img = load()
    va = None
    n = 30
    mode = "plain"
    for i, a in enumerate(argv):
        if a == "--va":
            va = int(argv[i + 1], 16) if not argv[i + 1].startswith("0x") else int(argv[i + 1], 16)
        elif a == "--n":
            n = int(argv[i + 1])
        elif a in ("--prologue", "--callers", "--str"):
            mode = a[2:]
        elif a == "--kw":
            pass
    if mode == "str":
        kw = argv[argv.index("--str") + 1]
        needle = kw.encode("utf-8")
        print(f"搜 '{kw}':", len([m for m in re.finditer(re.escape(needle), img)]), "命中")
        for m in re.finditer(re.escape(needle), img):
            print(f"  0x{BASE+m.start():x}")
        return 0
    if va is None:
        print(__doc__)
        return 1
    if mode == "callers":
        callers(img, va)
        return 0
    if mode == "prologue":
        va = find_prologue(img, va)
        print(f"[函数头] 0x{va:x}")
    print(f"--- 反汇编 0x{va:x} ---")
    dis(img, va, n)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
