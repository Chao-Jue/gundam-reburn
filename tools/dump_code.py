#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""只读地 dump 一段壳内代码（**不装任何 hook**）。

为什么单独写一个：`probe_light.py` 会挂 cB/cA/ws2 等一堆钩子，虽然昨天没崩，
但 0x7d5009 那种高频函数一 hook 就会触发 Themida 完整性校验把进程杀掉。
本脚本只 `readByteArray`，**一个字节都不改**，壳查不出来。

⚠️ 需要管理员权限（客户端是提权启动的），一般由 `tools\dump_code.cmd` 拉起。

用法：
    python tools/dump_code.py --pid 1234 --rva 0x7d4000,0x7d4200 --len 512 --out server/code_dump.json
    python tools/dump_code.py --follow --rva 0x7d4000 --len 512       # 等客户端出现
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
var base = mod.base;
var offs = %s;
var out = { base: base.toString(), items: {} };
for (var i = 0; i < offs.length; i++) {
  var off = offs[i];
  try {
    var b = new Uint8Array(base.add(off - 0x400000).readByteArray(%d));
    out.items[off] = Array.from(b).map(function (x) {
      return x.toString(16).padStart(2, '0');
    }).join('');
  } catch (e) {
    out.items[off] = 'ERR:' + String(e);
  }
}
send(out);
'''


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
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--rva", required=True)
    ap.add_argument("--len", type=int, default=512)
    ap.add_argument("--out", default=str(ROOT / "server" / "code_dump.json"))
    a = ap.parse_args()

    offs = [int(x.strip(), 0) for x in a.rva.split(",") if x.strip()]

    pid = a.pid
    if a.follow or not pid:
        print("[i] waiting for %s ..." % MOD, flush=True)
        for _ in range(300):
            pid = find_pid()
            if pid:
                break
            time.sleep(1)
    if not pid:
        print("[X] client not found", file=sys.stderr)
        return 2

    print("[i] attaching pid=%d ..." % pid, flush=True)
    sess = frida.attach(pid)
    sc = sess.create_script(JS % (MOD, json.dumps(offs), a.len))
    box: list = []
    sc.on("message", lambda m, d: box.append(m))
    sc.load()

    for _ in range(50):
        if box:
            break
        time.sleep(0.1)
    sess.detach()

    if not box:
        print("[X] no data", file=sys.stderr)
        return 3

    payload = box[0].get("payload") or {}
    Path(a.out).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    ok = sum(1 for v in (payload.get("items") or {}).values() if not str(v).startswith("ERR"))
    print("[+] dumped %d/%d segments -> %s" % (ok, len(offs), a.out), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
