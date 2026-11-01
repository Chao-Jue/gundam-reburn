#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""在整个主模块里搜某个 4 字节值的引用（只读 Memory.scan，不装 hook）。

用途：找"谁引用了 0x7d5004/0x7d5009 这个函数地址"——
      如果找不到 `call rel32`，说明它是**虚函数**，vtable 里会存这个地址。

用法：
    python tools/scan_ref.py --pid 1234 --value 0x7d5004
    python tools/scan_ref.py --pid 1234 --value 0x7d5004,0x7d5009
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import frida

ROOT = Path(__file__).resolve().parent.parent
MOD = "GundamOnline_CHINA.exe"

JS = r'''
var mod = Process.getModuleByName('%s');
var pats = %s;
var out = { base: mod.base.toString(), size: mod.size, hits: {} };
var ranges = [];
// ⚠️ 壳解包出来的代码段是 **rwx**，只用 'r-x' 枚举会漏掉它们（踩过这个坑）
['rwx', 'r-x', 'rw-', 'r--'].forEach(function (prot) {
  try { ranges = ranges.concat(Process.enumerateRanges(prot)); } catch (e) {}
});
for (var k = 0; k < pats.length; k++) {
  var p = pats[k], hits = [];
  for (var i = 0; i < ranges.length; i++) {
    var r = ranges[i];
    try {
      var res = Memory.scanSync(ptr(r.base), r.size, p.pattern);
      for (var j = 0; j < res.length; j++) {
        hits.push({ addr: res[j].address.toString(),
                    rva: res[j].address.sub(mod.base).toInt32() >>> 0,
                    prot: r.protection });
      }
    } catch (e) {}
  }
  out.hits[p.hex] = hits;
}
send(out);
'''


def le_hex(v: int) -> str:
    return ' '.join('%02x' % b for b in v.to_bytes(4, 'little'))


def find_pid() -> int | None:
    try:
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True)
        txt = out.stdout.decode("mbcs", "replace")
        for line in txt.splitlines():
            if "gundamonline_china" in line.lower():
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2 and parts[1].isdigit():
                    return int(parts[1])
    except Exception:
        pass
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=lambda s: int(s, 0))
    ap.add_argument("--value", default="", help="逗号分隔的 u32，如 0x7d5004,0x7d5009")
    ap.add_argument("--pattern", default="", help="原始字节模式，如 '8b 86 18 45 00 00'")
    a = ap.parse_args()

    pats = []
    for x in (a.value or "").split(','):
        x = x.strip()
        if x:
            v = int(x, 0)
            pats.append({"hex": hex(v), "pattern": le_hex(v)})
    for x in (a.pattern or "").split(';'):
        x = x.strip()
        if x:
            pats.append({"hex": x, "pattern": x})
    if not pats:
        ap.error("need --value or --pattern")

    pid = a.pid or find_pid()
    if not pid:
        print("[X] client not found", file=sys.stderr)
        return 2

    sess = frida.attach(pid)
    sc = sess.create_script(JS % (MOD, json.dumps(pats)))
    box: list = []
    sc.on("message", lambda m, d: box.append(m))
    sc.load()
    for _ in range(100):
        if box:
            break
        time.sleep(0.1)
    sess.detach()

    if not box:
        print("[X] no result", file=sys.stderr)
        return 3
    p = box[0].get("payload") or {}
    print("base=%s size=%s" % (p.get("base"), p.get("size")))
    for k, hits in (p.get("hits") or {}).items():
        print("=== refs to %s : %d ===" % (k, len(hits)))
        for h in hits[:40]:
            print("  RVA 0x%08x  (VA %s)  %s" % (h["rva"], h["addr"], h["prot"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
