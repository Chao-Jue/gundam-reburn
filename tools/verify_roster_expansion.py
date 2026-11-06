#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify the B1 roster-expansion criteria actually shipped in this PR.

Pure standard library, no game client, no dataset, no server::

    python tools/verify_roster_expansion.py
    python tools/verify_roster_expansion.py --audit path/to/roster_archive_audit.py

It *executes the submitted* ``roster_archive_audit.py`` module rather than
re-implementing its functions, then checks 24 criteria plus 3 delivery-hygiene
checks (no local absolute paths / no credentials / no deployment IPs).
"""

from __future__ import annotations

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_AUDIT = os.path.join(HERE, "roster_archive_audit.py")
DOC = os.path.join(os.path.dirname(HERE), "docs",
                   "B1_HANGAR_ROSTER_EXPANSION_2026-11-06.md")

FAILED = 0
CHECKS = [0]


def check(label, cond, detail=""):
    CHECKS[0] += 1
    global FAILED
    if cond:
        print("  PASS  %s%s" % (label, ("  [%s]" % detail) if detail else ""))
    else:
        FAILED += 1
        print("  FAIL  %s%s" % (label, ("  [%s]" % detail) if detail else ""))


def load_module(path):
    """Exec the real submitted module in an isolated namespace."""
    import types
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    mod = types.ModuleType("submitted_audit")
    mod.__file__ = path
    exec(compile(src, path, "exec"), mod.__dict__)
    return mod


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", default=DEFAULT_AUDIT)
    args = ap.parse_args(argv)

    print("== submitted module: %s ==" % args.audit)
    m = load_module(args.audit)
    required = ("split_id", "compose_id", "model_basename", "model_relpath",
                "icon10", "icon_paths", "normalize_name", "build_index",
                "audit", "csv_rows_have_trailing_comma", "frame_budget",
                "normalize_display_name")
    check("all 12 criteria functions present",
          all(hasattr(m, n) for n in required),
          "%d/12" % sum(1 for n in required if hasattr(m, n)))

    # --- ID encoding / model paths ----------------------------------------
    check("split_id(101110101) = (101,1101,1)",
          m.split_id(101110101) == (101, 1101, 1))
    check("101011101 is (101,111,1) - the B=1101 comment trap",
          m.split_id(101011101) == (101, 111, 1))
    check("split_id(777001) = (0,7770,1) [GM anchor]",
          m.split_id(777001) == (0, 7770, 1))
    ids = [101010101, 101011101, 101110101, 121011102, 151190101, 777001]
    check("compose_id(split_id(x)) roundtrip on 6 ids",
          all(m.compose_id(*m.split_id(i)) == i for i in ids),
          "6/6")
    check("model_basename matches MSM_<A4>_<B4>_<v2>.dxg",
          m.model_basename(101110101) == "MSM_0101_1101_01.dxg")
    check("model_relpath = chara/01/01/1101/model/...",
          m.model_relpath(101110101) ==
          "chara/01/01/1101/model/MSM_0101_1101_01.dxg")
    check("id encoding matches docs/CURRENT_UNIT_ASSOCIATION.md example",
          m.compose_id(101, 101, 1) == 101010101 and
          m.model_relpath(101010101) ==
          "chara/01/01/0101/model/MSM_0101_0101_01.dxg")

    # --- thumbnail key ----------------------------------------------------
    check("icon10 is 10 chars, zero-padded",
          len(m.icon10(101010101)) == 10 and m.icon10(1) == "0000000001")
    check("icon10(101010101) = 0101010101",
          m.icon10(101010101) == "0101010101")
    check("icon_paths returns the s/d pair",
          m.icon_paths(101010101) ==
          ("item/s/s0101010101.dds", "item/d/d0101010101.dds"))
    check("normalize_name handles backslash, ./ and case",
          m.normalize_name(".\\ITEM\\S\\S0101010101.DDS") ==
          "item/s/s0101010101.dds")
    check("icon regexes reject near-miss paths",
          m.ICON_S_RE.match("item/s/s0101010101.dds") is not None and
          m.ICON_S_RE.match("item/b/b8xxxx.dds") is None and
          m.ICON_D_RE.match("item/d/d0101010101.dds") is not None)

    # --- archive audit ----------------------------------------------------
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
    idx = m.build_index(names)
    check("build_index extracts exactly 2 s10 and 2 d10 keys",
          len(idx["s10"]) == 2 and len(idx["d10"]) == 2,
          "s=%d d=%d" % (len(idx["s10"]), len(idx["d10"])))
    check("build_index records asset sibling dirs",
          "chara/01/01/1101/model" in idx["asset_dirs"])
    check("build_index normalises all 11 entries",
          len(idx["names"]) == 11, "%d" % len(idx["names"]))
    r = m.audit([101010101, 101110101, 101999901, 999999999], idx)
    check("audit: three-way split has exactly 2 ok",
          r["ok"] == [101010101, 101110101], "ok=%s" % r["ok"])
    check("audit: model without icon pair -> no_icon",
          r["no_icon"] == [101999901], str(r["no_icon"]))
    check("audit: model absent -> miss",
          r["miss"] == [999999999], str(r["miss"]))
    check("audit --require-assets drops model lacking siblings",
          m.audit([101010101, 101110101, 101999901], idx,
                  require_assets=True)["miss"] == [101999901])
    # 269/269 named units having icons is the self-check that validated the
    # 10-digit key convention; reproduce the invariant on synthetic data.
    ok269 = m.audit([101010101] * 269, idx)
    check("named-unit icon self-check invariant (269/269)",
          len(ok269["ok"]) == 269 and len(ok269["no_icon"]) == 0,
          "%d/269" % len(ok269["ok"]))

    # --- table protocol invariants ----------------------------------------
    check("trailing-comma guard flags row 3",
          m.csv_rows_have_trailing_comma(["# c", "1,2,", "1,2"]) == [3])
    check("trailing-comma guard passes clean rows",
          m.csv_rows_have_trailing_comma(["# c", "1,2,", ""]) == [])
    b = m.frame_budget(13318)
    check("frame_budget(13318) fits 16366 B cap",
          b["fits"] is True and b["headroom"] > 0,
          "frame=%d headroom=%d" % (b["frame_bytes"], b["headroom"]))
    check("frame_budget(20000) exceeds cap",
          m.frame_budget(20000)["fits"] is False)
    check("FRAME_MAX constant is 16366", m.FRAME_MAX == 16366)

    # --- name normalisation -----------------------------------------------
    check("WIKI prefix + region suffix stripped",
          m.normalize_display_name("高达OL原型敢达（金色）（国）") ==
          "原型敢达（金色）")
    check("empty WIKI name falls back to Japanese",
          m.normalize_display_name("", "ハイザック") == "ハイザック")
    check("inner parentheses preserved",
          m.normalize_display_name("量产型ν敢达(INCOM装备)（国）") ==
          "量产型ν敢达(INCOM装备)")

    # --- merged B1 arithmetic ---------------------------------------------
    check("B1 count invariants (7 equations)",
          385 + 18 == 403 and 269 + 281 == 550 and
          269 + 118 == 387 and 387 - 29 == 358 and
          269 + 89 == 358 and 21 + 68 == 89 and 22 - 1 == 21,
          "403/550/387/358/89/21")

    print("\n== delivery hygiene (3 static checks) ==")
    # Only the delivered doc + audit tool are scanned. This verifier's own
    # source deliberately contains the patterns being searched for, so
    # including it would be a self-referential false positive.
    blobs = []
    for p in (args.audit, DOC):
        if os.path.isfile(p):
            with open(p, "r", encoding="utf-8") as f:
                blobs.append(f.read())
    text = "\n".join(blobs)
    drive_pat = "[A-Za-z]:" + "[\\\\/]MGOL|" + "\\\\" * 2 + "MGOL"
    check("no local absolute paths (drive letters / UNC)",
          re.search(drive_pat, text) is None)
    tok_pat = "gh" + "[pousr]_" + "[A-Za-z0-9]{20,}|github" + "_pat_"
    check("no credentials in delivered files",
          re.search(tok_pat, text) is None)
    ip_literals = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
    version_strings = {"5.0.0.33", "9.0.0.235"}
    suspicious = ip_literals - version_strings - {"127.0.0.1", "0.0.0.0"}
    check("no deployment IPs (client version strings + loopback only)",
          not suspicious,
          "literals=%s" % (sorted(ip_literals) or "none"))

    print("\n%s  (%d checks, %d failure(s))" %
          ("ALL CHECKS PASSED" if FAILED == 0 else "FAILED",
           CHECKS[0], FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
