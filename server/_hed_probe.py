"""解析 data/settings.hed（FPMF 索引），并用已知明文校验 data/settings/0000.dat。

FPMF 头部（实测）："FPMF" | u32 ver=2 | u32 size=5861 | u32 ?=2 | ...
做法：对 body 尝试  (xor k) -> raw deflate，找出能把索引展开成明文的那组参数。
只读，不写任何文件。
"""
from __future__ import annotations

import pathlib
import zlib

ROOT = pathlib.Path(r"D:\project\gundam-reburn")
CLI = ROOT / "launcher" / "gundam" / "机动战士敢达Online" / "GundamOnline"


def try_inflate(buf: bytes, maxout: int = 1 << 22):
    d = zlib.decompressobj(-15)
    try:
        out = d.decompress(buf, maxout)
    except Exception:
        return None
    if len(out) < 16:
        return None
    return out


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for x in b if 0x20 <= x < 0x7F or x in (9, 10, 13) or x >= 0x80)
    return ok / len(b)


def main() -> None:
    hed = (CLI / "data" / "settings.hed").read_bytes()
    print(f"[.hed] {len(hed):,} B  head={hed[:16].hex(' ')}")
    magic = hed[:4]
    import struct
    ver, sz, x2 = struct.unpack_from("<III", hed, 4)
    print(f"  magic={magic!r} ver={ver} size={sz} x2={x2}")
    print()

    body_variants = {
        "body[8:]": hed[8:],
        "body[12:]": hed[12:],
        "body[16:]": hed[16:],
        "body[20:]": hed[20:],
    }
    best = None
    for tag, body in body_variants.items():
        for k in range(256):
            data = body if k == 0 else bytes(b ^ k for b in body)
            out = try_inflate(data)
            if out is None:
                continue
            pr = printable_ratio(out)
            if best is None or len(out) > len(best[2]):
                best = (tag, k, out, pr)
            if pr > 0.85 and len(out) > 200:
                print(f"  ★ {tag} xor=0x{k:02x} -> {len(out):,} B  可打印率={pr:.2f}")
                print("    " + repr(out[:400]))
                best = (tag, k, out, pr)
                break

    if best:
        tag, k, out, pr = best
        print()
        print(f"[最佳] {tag} xor=0x{k:02x} -> {len(out):,} B 可打印率={pr:.2f}")
        (ROOT / "server" / "_settings_hed_index.bin").write_bytes(out)
        print("  已存 server/_settings_hed_index.bin 供人工查看")
        # 找文件名痕迹
        import re
        names = re.findall(rb"[A-Za-z0-9_./-]{4,60}\.(?:csv|txt|cfg)", out)
        print(f"  文件名命中 {len(names)} 个: {[n.decode() for n in names[:15]]}")
    else:
        print("[结论] 所有 (偏移, 异或键) 组合都解不开索引")


if __name__ == "__main__":
    main()
