#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify the optional 0x5290 table-body compression added to server/fake_auth.py.

Pure standard library, no game client, no dataset and no server needed::

    python tools/verify_table_compress.py
    python tools/verify_table_compress.py --fake-auth path/to/fake_auth.py

It extracts the *real* ``datafile_block`` / ``_kind0`` / ``_align_message``
source out of the submitted fake_auth.py (via AST) and runs it in a small
sandbox, so the test covers the code that is actually in the PR, not a
re-implementation.
"""

import argparse
import ast
import os
import sys
import zlib

FRAME_MAX = 16366
OPCODE = (0x5290).to_bytes(2, "little")
NEEDED = ("_align_message", "_kind0", "datafile_block")


def load_submitted(path):
    """Exec only the three functions from fake_auth.py in an isolated namespace."""
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src, filename=path)
    segs = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in NEEDED:
            segs[node.name] = ast.get_source_segment(src, node)
    missing = [n for n in NEEDED if n not in segs]
    if missing:
        raise SystemExit("functions not found in %s: %s" % (path, missing))
    logs = []
    ns = {
        "missing_body": lambda name: b"####\n",   # same shape as upstream placeholder
        "log": logs.append,
    }
    for name in NEEDED:
        exec(compile(segs[name], path, "exec"), ns)
    return ns["datafile_block"], ns["_kind0"], ns["_align_message"], logs


def parse_frame(hexstr):
    """Undo _kind0 + _align_message and decode the 0x5290 body fields."""
    raw = bytes.fromhex(hexstr)
    kind = raw[0]
    width = kind + 1
    n = int.from_bytes(raw[1:1 + width], "little")
    head = 1 + width
    payload = raw[head:head + n]
    if payload[:2] != OPCODE:
        raise AssertionError("bad opcode: %r" % payload[:2])
    body = payload[2:]
    off = 4                                   # u32 result
    end = body.index(0, off)                  # NUL-terminated filepath
    name = body[off:end].decode("ascii")
    off = end + 1
    off += 4                                  # u32 hash (client ignores it)
    src_bytes = int.from_bytes(body[off:off + 4], "little"); off += 4
    compress = int.from_bytes(body[off:off + 2], "little"); off += 2
    bin_len = int.from_bytes(body[off:off + 4], "little"); off += 4
    blob = body[off:off + bin_len]
    if len(blob) != bin_len:
        raise AssertionError("truncated body: %d != %d" % (len(blob), bin_len))
    return dict(name=name, src_bytes=src_bytes, compress=compress,
                bin_len=bin_len, blob=blob, frame=len(raw), raw=raw)


def legacy_block(name, data, kind0, align, result=0):
    """The original upstream implementation, for byte-for-byte comparison."""
    raw = name.encode("ascii", "replace")
    if len(raw) >= 0x100:
        raw = raw[:0xFF]
    if not data:
        data = b"####\n"
    body = (((result or 0) & 0xFFFFFFFF).to_bytes(4, "little")
            + raw + b"\x00"
            + (0).to_bytes(4, "little")
            + len(data).to_bytes(4, "little")
            + (0).to_bytes(2, "little")
            + len(data).to_bytes(4, "little")
            + data)
    return align(kind0(OPCODE + body)).hex()


def make_table(rows, cols=24):
    """A repetitive CSV-ish table body, like the real msma_* tables."""
    head = (",".join("C%d" % i for i in range(cols)) + "\n").encode()
    line = (",".join("101010101" for _ in range(cols)) + "\n").encode()
    return b"\xef\xbb\xbf" + head + line * rows


def check(title, cond, detail=""):
    global FAILED
    print("  [%s] %-58s %s" % ("PASS" if cond else "FAIL", title, detail))
    if not cond:
        FAILED += 1
    return cond


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fake-auth", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "server", "fake_auth.py"))
    args = ap.parse_args()
    path = os.path.abspath(args.fake_auth)
    print("fake_auth.py : %s" % path)
    block, kind0, align, logs = load_submitted(path)

    def run(name, data, mode, min_bytes="2048"):
        prev = (os.environ.get("MSGO_TABLE_COMPRESS"),
                os.environ.get("MSGO_TABLE_COMPRESS_MIN"))
        os.environ["MSGO_TABLE_COMPRESS"] = mode
        os.environ["MSGO_TABLE_COMPRESS_MIN"] = min_bytes
        try:
            return parse_frame(block(name, data))
        finally:
            for k, v in zip(("MSGO_TABLE_COMPRESS", "MSGO_TABLE_COMPRESS_MIN"), prev):
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    print("\n== 1. default mode is byte-identical to the original ==")
    cases = [
        ("msma/msma_weapon_set.csv", b"####\n"),
        ("autoexec_sv.cfg", b"X\n"),
        ("msma/msma_settings.csv", make_table(80)),
        ("", b"hello world\n"),
    ]
    for name, data in cases:
        # force mode=0 so a dirty caller environment cannot affect this check
        mine = parse_frame(_with_mode(block, name, data, "0"))
        want = parse_frame(legacy_block(name, data, kind0, align))
        check("raw frame identical: %s" % (name or "<empty>"),
              mine["raw"] == want["raw"] and mine["compress"] == 0,
              "%d B" % mine["frame"])

    print("\n== 2. auto compresses a big table and round-trips ==")
    big = make_table(540)                     # ~130 KB, like 358-suit msma_settings
    r = run("msma/msma_settings.csv", big, "auto")
    print("     raw %d B -> wire %d B (%.1f%%), frame %d B"
          % (len(big), r["bin_len"], 100.0 * r["bin_len"] / len(big), r["frame"]))
    check("compress flag == 1", r["compress"] == 1)
    check("src_bytes == uncompressed length", r["src_bytes"] == len(big),
          "src_bytes=%d" % r["src_bytes"])
    check("bin_len == compressed length", r["bin_len"] == len(r["blob"]))
    check("zlib round-trip is exact", zlib.decompress(r["blob"]) == big)
    check("frame below 16366 B hard limit", r["frame"] < FRAME_MAX,
          "%d B" % r["frame"])
    raw_frame = run("msma/msma_settings.csv", big, "0")["frame"]
    check("raw mode would have exceeded the limit", raw_frame > FRAME_MAX,
          "%d B" % raw_frame)
    check("oversize raw frame emitted a warning",
          any("16366" in m for m in logs), "%d log lines" % len(logs))

    print("\n== 3. auto leaves small / incompressible tables alone ==")
    small = make_table(4)                     # ~1 KB, below the 2048 B threshold
    r2 = run("msma/msma_model.csv", small, "auto")
    check("small table stays raw", r2["compress"] == 0 and r2["blob"] == small,
          "%d B" % len(small))
    noisy = os.urandom(6000)
    r3 = run("msma/msma_model.csv", noisy, "auto")
    check("incompressible table stays raw", r3["compress"] == 0 and r3["blob"] == noisy,
          "%d B" % len(noisy))

    print("\n== 4. mode=1 forces compression even for small bodies ==")
    r4 = run("autoexec_sv.cfg", small, "1")
    check("forced compress flag == 1", r4["compress"] == 1)
    check("forced round-trip is exact", zlib.decompress(r4["blob"]) == small)

    print("\n== 5. MSGO_TABLE_COMPRESS_MIN threshold is honoured ==")
    r5 = run("msma/msma_settings.csv", big, "auto", min_bytes="999999")
    check("big table skipped when below threshold", r5["compress"] == 0)

    print("\n== 6. why src_bytes must be the *inflated* length ==")
    # Client does calloc(src_bytes) then inflate() into that buffer. Emulate a
    # wrong (compressed-size) value: streaming inflate with that max_length is
    # truncated, and the client does not check the return value.
    wrong_cap = r["bin_len"]
    d = zlib.decompressobj()
    truncated = d.decompress(r["blob"], wrong_cap)
    check("inflating into a wrong-sized buffer truncates silently",
          len(truncated) == wrong_cap and len(truncated) < len(big),
          "%d of %d B" % (len(truncated), len(big)))
    check("correct src_bytes inflates fully",
          len(zlib.decompress(r["blob"])) == r["src_bytes"] == len(big))

    print("\n%s  (%d failure(s))" % ("ALL CHECKS PASSED" if FAILED == 0 else "FAILED", FAILED))
    return 1 if FAILED else 0


def _with_mode(block, name, data, mode):
    prev = os.environ.get("MSGO_TABLE_COMPRESS")
    os.environ["MSGO_TABLE_COMPRESS"] = mode
    try:
        return block(name, data)
    finally:
        if prev is None:
            os.environ.pop("MSGO_TABLE_COMPRESS", None)
        else:
            os.environ["MSGO_TABLE_COMPRESS"] = prev


FAILED = 0

if __name__ == "__main__":
    sys.exit(main())
