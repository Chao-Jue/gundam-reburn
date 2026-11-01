#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""尝试解开 FPMF(.hed) 的 body —— 判断它到底是不是 zlib/简单异或。

背景：客户端 `data/*.hed` 是 FPMF 容器，头是明文（`tools/fpmf_info.py` 能读），
但 body「不是明文」。而进程里加载了 `zlib1.dll`，所以先按 zlib 各种 wbits 试；
再试单字节异或 + zlib。

用途：如果某个 .hed 解出来，就能全量搜「技术测试区」/`60.206.12.127` 这类
运行时才出现的字符串，从而定位内置兜底战区和服务器地址。

用法：
    python tools/hed_extract.py <hed 文件或目录> [--grep 关键字] [--dump 输出目录]
关键字按 GBK / UTF-8 / UTF-16LE 三种编码分别搜。
"""
from __future__ import annotations

import argparse
import sys
import zlib
from pathlib import Path

MAGIC = 0x464D5046
HDR = 16


def try_inflate(b: bytes) -> tuple[bytes | None, str]:
    """返回 (解压结果, 说明)。依次试常见 wbits 和头部偏移。"""
    for wbits in (47, 31, 15, -15):
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(b)
            if len(out) >= 64:
                return out, f"wbits={wbits}"
        except Exception:  # noqa: BLE001
            pass
    for off in range(0, min(64, len(b))):
        for wbits in (15, -15, 47):
            try:
                d = zlib.decompressobj(wbits)
                out = d.decompress(b[off:])
                if len(out) >= 128:
                    return out, f"off={off} wbits={wbits}"
            except Exception:  # noqa: BLE001
                pass
    return None, ""


def try_xor_inflate(b: bytes) -> tuple[bytes | None, str]:
    """单字节异或后再 zlib —— 有些老引擎就这么干。"""
    for k in range(1, 256):
        x = bytes(c ^ k for c in b[:4096])
        for wbits in (15, -15):
            try:
                d = zlib.decompressobj(wbits)
                if len(d.decompress(x)) >= 64:
                    full = bytes(c ^ k for c in b)
                    d2 = zlib.decompressobj(wbits)
                    out = d2.decompress(full)
                    return out, f"xor=0x{k:02x} wbits={wbits}"
            except Exception:  # noqa: BLE001
                pass
    return None, ""


def encodings(kw: str) -> list[tuple[str, bytes]]:
    out = []
    for name, enc in (("gbk", "gbk"), ("utf8", "utf-8"), ("utf16le", "utf-16-le")):
        try:
            out.append((name, kw.encode(enc)))
        except Exception:  # noqa: BLE001
            pass
    return out


def scan(data: bytes, kws: list[str]) -> list[str]:
    hits = []
    if not data:
        return hits
    for kw in kws:
        for nm, pat in encodings(kw):
            i = data.find(pat)
            if i >= 0:
                hits.append(f"{kw}[{nm}]@0x{i:x}")
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", type=Path)
    ap.add_argument("--grep", action="append", default=None,
                    help="关键字，可重复；默认搜 技术测试 / 战区 / 60.206.12.127")
    ap.add_argument("--dump", type=Path, default=None, help="解出来的数据写到这里")
    args = ap.parse_args()

    kws = args.grep or ["技术测试", "战区", "60.206.12.127", "authsv", "9you"]
    if args.dump:
        args.dump.mkdir(parents=True, exist_ok=True)

    files = sorted(args.root.rglob("*.hed")) if args.root.is_dir() else [args.root]
    print(f"{'file':<28} {'body':>9} {'方法':<22} 命中")
    for f in files:
        raw = f.read_bytes()
        if len(raw) < HDR or int.from_bytes(raw[:4], "little") != MAGIC:
            print(f"{f.name:<28} {'-':>9} {'(不是 FPMF)':<22}")
            continue
        body = raw[HDR:]
        got, how = try_inflate(body)
        if got is None:
            got, how = try_xor_inflate(body)
        if got is None:
            # 也许 body 就是明文，只是有别的包装
            got, how = body, "(原样)"
        hits = scan(got, kws)
        print(f"{f.name:<28} {len(body):>9} {how:<22} {', '.join(hits) if hits else '-'}")
        if args.dump and how != "(原样)":
            (args.dump / (f.stem + ".bin")).write_bytes(got)
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    raise SystemExit(main())
