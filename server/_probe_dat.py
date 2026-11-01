#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""探测 data/ 下分片 .dat 的封装：是不是 FPMF？能否用已知方法(xor0x43+raw-deflate)解开？

只读，不改任何文件。用法：
    python server/_probe_dat.py <文件或目录> [数量上限]
"""
from __future__ import annotations

import sys
import zlib
from pathlib import Path

MAGIC_FPMF = 0x464D5046


def head_hex(b: bytes, n: int = 32) -> str:
    return " ".join(f"{c:02x}" for c in b[:n])


def try_inflate(b: bytes):
    for wbits in (15, -15, 47, 31):
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(b)
            if len(out) >= 64:
                return out, f"inflate wbits={wbits}"
        except Exception:
            pass
    return None, ""


def try_xor_inflate(b: bytes, key: int):
    x = bytes(c ^ key for c in b[:8192])
    for wbits in (-15, 15, 47):
        try:
            d = zlib.decompressobj(wbits)
            if len(d.decompress(x)) >= 64:
                full = bytes(c ^ key for c in b)
                d2 = zlib.decompressobj(wbits)
                out = d2.decompress(full)
                return out, f"xor=0x{key:02x} inflate wbits={wbits}"
        except Exception:
            pass
    return None, ""


def probe(f: Path) -> str:
    raw = f.read_bytes()
    n = len(raw)
    magic = int.from_bytes(raw[:4], "little")
    tag = "FPMF" if magic == MAGIC_FPMF else f"0x{magic:08x}"
    # 若 FPMF，跳过 16 字节头
    body = raw[16:] if magic == MAGIC_FPMF else raw
    got, how = try_inflate(body)
    if got is None:
        # 试客户端的已知单字节异或键（0x43 优先，再扫 0..255）
        for k in [0x43] + [i for i in range(1, 256) if i != 0x43]:
            g, h = try_xor_inflate(body, k)
            if g is not None:
                got, how = g, h
                break
    if got is None:
        return (f"{f.name:<16} size={n:>9} magic={tag:<10} head={head_hex(raw)}"
                f"  => 未解开（可能非 zlib/异或）")
    # 解开后看看像不像文本
    sample = got[:64]
    printable = sum(1 for c in sample if 32 <= c < 127 or c in (9, 10, 13))
    kind = "文本" if printable > len(sample) * 0.8 else "二进制"
    return (f"{f.name:<16} size={n:>9} magic={tag:<10} => 解开! {how} "
            f"out={len(got)} 像{kind} head={head_hex(got)}")


def main() -> int:
    root = Path(sys.argv[1])
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    files = sorted(root.rglob("*.dat"))[:limit] if root.is_dir() else [root]
    for f in files:
        print(probe(f))
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
