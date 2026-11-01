"""Read the clear FPMF header on Gundam Online .hed indexes.

On-disk layout (little-endian), confirmed against the China client's
GundamOnline_CHINA.exe checker at VA 0x00b0f5f9:

    0x00  u32  magic   'FPMF' (0x464D5046)
    0x04  u32  version (2 on this client)
    0x08  u32  body size in bytes (file size minus this 16-byte header)
    0x0C  u32  segment count (2 on every archive in this tree)

The body is not plaintext. The client reads it as `segment count` chunks;
each chunk begins with an 8-byte header after the stream is opened. Those
bytes do not survive as sizes on disk, so this tool stops at the header.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

MAGIC = 0x464D5046
HEADER = struct.Struct("<4I")


def read_header(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) < HEADER.size:
        raise ValueError(f"{path} is shorter than an FPMF header")
    magic, version, body_size, segments = HEADER.unpack_from(data, 0)
    if magic != MAGIC:
        raise ValueError(f"{path} magic is {magic:#x}, expected FPMF")
    return {
        "path": path,
        "version": version,
        "body_size": body_size,
        "segments": segments,
        "file_size": len(data),
        "body_matches": body_size == len(data) - HEADER.size,
    }


def iter_hed(root: Path):
    if root.is_file():
        yield root
        return
    yield from sorted(root.rglob("*.hed"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Print FPMF headers")
    parser.add_argument("root", type=Path, help="a .hed file or a directory tree")
    args = parser.parse_args()
    rows = []
    for path in iter_hed(args.root):
        try:
            rows.append(read_header(path))
        except ValueError as exc:
            print(exc, file=sys.stderr)
    if not rows:
        print("no .hed files")
        return
    print(f"{'version':>7} {'segments':>8} {'body':>12} {'file':>12}  ok  path")
    bad = 0
    for row in rows:
        ok = "yes" if row["body_matches"] else "NO"
        if not row["body_matches"]:
            bad += 1
        print(
            f"{row['version']:7d} {row['segments']:8d} {row['body_size']:12d} "
            f"{row['file_size']:12d}  {ok}  {row['path']}"
        )
    print(f"{len(rows)} headers, {bad} size mismatches")


if __name__ == "__main__":
    main()
