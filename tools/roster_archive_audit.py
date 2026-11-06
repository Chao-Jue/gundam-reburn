#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reusable roster/resource criteria for hangar expansion (B1).

Pure standard library. No game client, no decryption, no dataset, no local
paths: you feed it a plain-text list of *archive entry names* that your own
HED index tooling has already exported, plus a list of candidate 9-digit
unit IDs. It answers three questions per ID:

    ok       model .dxg present AND s/d thumbnail pair present  -> safe to list
    no_icon  model present but thumbnail pair missing          -> cut (X11)
    miss     model .dxg absent                                 -> cannot list (X3)

Why this exists: judging "does this unit have resources?" from a decrypted
reference tree systematically overestimates. Only the real client archives
(data/chara/<AA>/<BB>.hed, data/interface/icon.hed) are authoritative.

Usage::

    python tools/roster_archive_audit.py --selftest
    python tools/roster_archive_audit.py \
        --index client_archive_index.txt \
        --candidates candidate_ids.txt \
        --out audit_report.json
    python tools/roster_archive_audit.py --index ... --candidates ... \
        --require-assets     # also demand tex/vra/motionlist.csv siblings

The index format is one path per line, e.g. (id 101010101)::

    chara/01/01/0101/model/MSM_0101_0101_01.dxg
    chara/01/01/0101/model/MSM_0101_0101_01C.dds
    ./item/s/s0101010101.dds
    ./item/d/d0101010101.dds

Lines starting with '#' and blank lines are ignored. Both '/' and '\\'
separators, a leading './', and case differences are normalised.

Version boundary: created against the MSGO 5.0.0.33 China client. The
criteria travel; the concrete counts, table layouts and exe addresses do not.
See docs/B1_HANGAR_ROSTER_EXPANSION_2026-11-06.md section 7.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

# --------------------------------------------------------------------------
# Core criteria
# --------------------------------------------------------------------------

FRAME_MAX = 16366                       # single-frame cap, see PR #7
ICON_S_RE = re.compile(r"^item/s/s(\d{10})\.dds$", re.I)
ICON_D_RE = re.compile(r"^item/d/d(\d{10})\.dds$", re.I)
MODEL_RE = re.compile(r"^MSM_(\d{4})_(\d{4})_(\d{2})\.dxg$", re.I)


def split_id(msma_id: int):
    """msma_id -> (A, B, variant).  A and B are 4-digit groups."""
    value = int(msma_id)
    return value // 1_000_000, (value // 100) % 10_000, value % 100


def compose_id(a: int, b: int, v: int) -> int:
    """Inverse of split_id."""
    return int(a) * 1_000_000 + int(b) * 100 + int(v)


def model_basename(msma_id: int) -> str:
    """The .dxg file name implied by a 9-digit unit id."""
    a, b, v = split_id(msma_id)
    return "MSM_%04d_%04d_%02d.dxg" % (a, b, v)


def model_relpath(msma_id: int) -> str:
    """Directory layout: chara/<A[0:2]>/<A[2:4]>/<B>/model/<file>."""
    a, b, v = split_id(msma_id)
    A4, B4 = "%04d" % a, "%04d" % b
    return "chara/%s/%s/%s/model/%s" % (A4[0:2], A4[2:4], B4,
                                        model_basename(msma_id))


def icon10(model_id: int) -> str:
    """9-digit model id -> the 10-digit key used in thumbnail filenames."""
    return "0" + str(int(model_id)).zfill(9)


def icon_paths(model_id: int):
    """The s/d pair that must both exist for a unit to be listable."""
    key = icon10(model_id)
    return ("item/s/s%s.dds" % key, "item/d/d%s.dds" % key)


def normalize_name(path: str) -> str:
    """Normalise one archive entry name for set membership."""
    name = str(path).strip().strip('"').replace("\\", "/")
    while name.startswith("./"):
        name = name[2:]
    return name.lstrip("/").lower()


def build_index(names):
    """Index a list of archive entry names.

    Returns dict with: names (normalised full paths), basenames, s10, d10,
    and asset_dirs (directories that contain a .dds/.vra/motionlist.csv).
    """
    full = set()
    bases = set()
    s10, d10 = set(), set()
    asset_dirs = set()
    for raw in names:
        n = normalize_name(raw)
        if not n:
            continue
        full.add(n)
        base = n.rsplit("/", 1)[-1]
        bases.add(base)
        m = ICON_S_RE.match(n)
        if m:
            s10.add(m.group(1))
            continue
        m = ICON_D_RE.match(n)
        if m:
            d10.add(m.group(1))
            continue
        lb = base.lower()
        if lb.endswith((".dds", ".vra")) or lb == "motionlist.csv":
            asset_dirs.add(n.rsplit("/", 1)[0] if "/" in n else "")
    return {"names": full, "basenames": bases, "s10": s10, "d10": d10,
            "asset_dirs": asset_dirs}


def audit(candidates, index, require_assets=False):
    """Classify each candidate id as ok / no_icon / miss.

    `candidates` is an iterable of 9-digit ints (or numeric strings).
    `index` is the dict returned by build_index().
    """
    out = {"ok": [], "no_icon": [], "miss": []}
    for cid in candidates:
        mid = int(cid)
        base = model_basename(mid)
        model_found = base.lower() in index["basenames"] or \
            model_relpath(mid).lower() in index["names"]
        if not model_found:
            out["miss"].append(mid)
            continue
        if require_assets:
            d = model_relpath(mid).lower().rsplit("/", 1)[0]
            if d not in index["asset_dirs"]:
                out["miss"].append(mid)
                continue
        key = icon10(mid)
        if key in index["s10"] and key in index["d10"]:
            out["ok"].append(mid)
        else:
            out["no_icon"].append(mid)
    for k in out:
        out[k].sort()
    return out


# --------------------------------------------------------------------------
# Two table-protocol invariants that bit us repeatedly (documented, testable)
# --------------------------------------------------------------------------

def csv_rows_have_trailing_comma(rows):
    """Every non-comment, non-empty CSV data row must end with a comma."""
    bad = []
    for i, row in enumerate(rows, 1):
        s = str(row).rstrip("\r\n")
        if not s or s.lstrip().startswith("#"):
            continue
        if not s.endswith(","):
            bad.append(i)
    return bad


def frame_budget(body_len: int, frame_overhead: int = 0x12 + 2 + 4 + 4 + 2 + 4):
    """Body size -> (frame size, fits 16366 B cap, headroom)."""
    size = frame_overhead + int(body_len)
    return {"frame_bytes": size, "fits": size <= FRAME_MAX,
            "headroom": FRAME_MAX - size}


def normalize_display_name(wiki_name: str, jp_name: str = "") -> str:
    """Chinese WIKI name first; strip product prefix and region suffix.

    Falls back to the Japanese name when the WIKI name is empty.
    """
    s = (wiki_name or "").strip()
    if not s:
        return (jp_name or "").strip()
    s = re.sub(r"^高达OL", "", s)
    s = re.sub(r"[（(](国|日)[）)]\s*$", "", s).strip()
    return s


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def read_lines(path):
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                yield s


def selftest():
    """Self-contained checks, no external files."""
    fails = []
    total = [0]

    def ck(label, cond, detail=""):
        total[0] += 1
        if not cond:
            fails.append("%s%s" % (label, ("  [%s]" % detail) if detail else ""))

    ck("split_id 101110101 = (101,1101,1)",
       split_id(101110101) == (101, 1101, 1))
    # A hand-written comment in our local generator claimed 101011101 has
    # B=1101; it does not. Keep this trap as an explicit regression check.
    ck("split_id 101011101 is (101,111,1), NOT B=1101",
       split_id(101011101) == (101, 111, 1))
    ck("split_id 777001", split_id(777001) == (0, 7770, 1))
    ck("compose_id roundtrip", compose_id(101, 1101, 1) == 101110101)
    ck("model_basename", model_basename(101110101) == "MSM_0101_1101_01.dxg")
    ck("model_relpath",
       model_relpath(101110101) ==
       "chara/01/01/1101/model/MSM_0101_1101_01.dxg")
    ck("icon10 width", len(icon10(101010101)) == 10)
    ck("icon10 value", icon10(101010101) == "0101010101")
    ck("icon10 leading zero", icon10(1) == "0000000001")
    ck("icon_paths", icon_paths(101010101) ==
       ("item/s/s0101010101.dds", "item/d/d0101010101.dds"))
    ck("normalize_name backslash",
       normalize_name(".\\item\\S\\S0101010101.DDS") ==
       "item/s/s0101010101.dds")

    names = [
        "./item/s/s0101010101.dds", "./item/d/d0101010101.dds",
        "./item/s/s0101110101.dds", "./item/d/d0101110101.dds",
        "chara/01/01/0101/model/MSM_0101_0101_01.dxg",
        "chara/01/01/0101/model/MSM_0101_0101_01C.dds",
        "chara/01/01/0101/model/motionlist.csv",
        "chara/01/01/1101/model/MSM_0101_1101_01.dxg",
        "chara/01/01/1101/model/MSM_0101_1101_01C.dds",
        "chara/01/01/1101/model/motionlist.csv",
        "chara/01/01/9999/model/MSM_0101_9999_01.dxg",
    ]
    idx = build_index(names)
    ck("build_index s10", "0101010101" in idx["s10"])
    ck("build_index d10", "0101010101" in idx["d10"])
    ck("build_index asset_dir",
       "chara/01/01/0101/model" in idx["asset_dirs"])
    r = audit([101010101, 101110101, 101999901, 999999999], idx)
    ck("audit ok", r["ok"] == [101010101, 101110101], str(r["ok"]))
    ck("audit no_icon", r["no_icon"] == [101999901], str(r["no_icon"]))
    ck("audit miss", r["miss"] == [999999999], str(r["miss"]))
    ck("audit require_assets drops model lacking siblings",
       audit([101010101, 101110101, 101999901], idx,
             require_assets=True)["miss"] == [101999901])
    ck("trailing comma detect",
       csv_rows_have_trailing_comma(["# comment", "1,2,", "1,2"]) == [3])
    ck("trailing comma clean",
       csv_rows_have_trailing_comma(["# c", "1,2,"]) == [])
    ck("frame fits", frame_budget(13318 - 64)["fits"] is True)
    ck("frame overflow", frame_budget(16366)["fits"] is False)
    ck("wiki prefix strip",
       normalize_display_name("高达OL原型敢达（金色）（国）") == "原型敢达（金色）")
    ck("jp fallback",
       normalize_display_name("", "ハイザック") == "ハイザック")
    ck("keep inner parentheses",
       normalize_display_name("量产型ν敢达(INCOM装备)（国）") ==
       "量产型ν敢达(INCOM装备)")

    # The arithmetic invariants recorded in the merged B1 write-up.
    ck("403 = 385 + 18", 385 + 18 == 403)
    ck("550 = 269 + 281", 269 + 281 == 550)
    ck("269 + 118 = 387", 269 + 118 == 387)
    ck("387 - 29 = 358", 387 - 29 == 358)
    ck("358 = 269 + 89", 269 + 89 == 358)
    ck("89 = 21 + 68", 21 + 68 == 89)
    ck("22 - 1 overlap = 21", 22 - 1 == 21)

    for label in fails:
        print("FAIL:", label)
    print("roster_archive_audit selftest: %d checks, %d failure(s)" %
          (total[0], len(fails)))
    return 1 if fails else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--index", help="text file, one archive entry path per line")
    ap.add_argument("--candidates", help="text file, one 9-digit id per line")
    ap.add_argument("--out", help="write the JSON report here (default: stdout)")
    ap.add_argument("--require-assets", action="store_true",
                    help="also require tex/vra/motionlist.csv siblings")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.index or not args.candidates:
        ap.error("--index and --candidates are required (or use --selftest)")

    idx = build_index(read_lines(args.index))
    cands = []
    for line in read_lines(args.candidates):
        token = line.split(",")[0].strip()
        if token.isdigit():
            cands.append(int(token))
    report = {
        "index_records": len(idx["names"]),
        "s10_keys": len(idx["s10"]),
        "d10_keys": len(idx["d10"]),
        "candidates": len(cands),
        "require_assets": args.require_assets,
        "result": audit(cands, idx, args.require_assets),
    }
    report["summary"] = {k: len(v) for k, v in report["result"].items()}
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print("wrote %s (ok=%d no_icon=%d miss=%d)" %
              (args.out, report["summary"]["ok"],
               report["summary"]["no_icon"], report["summary"]["miss"]))
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
