#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""极简探针：只 hook 收包分发器 0x7d5009，把 32 位消息 ID 打出来。

⚠️ 必须用**管理员权限**运行：客户端是提权启动的，普通用户 attach 会得到
   `frida.PermissionDeniedError: unable to access process ... from the current user account`
   （别把它误判成"frida 挂了"）。一般由 tools/start_local.cmd 以 `start /min` 拉起。

用法：
    python tools/hook_msgid.py --follow      # 等客户端出现再挂（推荐，.cmd 里就是这么起的）
    python tools/hook_msgid.py 548           # 指定 pid

输出（server/msgid.log）：
    {"msgid": "4ff84464", "known": true, "bt": [...]}
    {"boot": "hooked 0x7d5009"}
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
LOG = ROOT / "server" / "msgid.log"
MOD = "GundamOnline_CHINA"

JS = r'''
var mod = Process.getModuleByName('GundamOnline_CHINA.exe');
var base = mod.base;
var KNOWN = [0x1691BE88,0x1849D46B,0x29460E2C,0x3C7D17C8,0x41B41611,
             0x4FF84464,0x6B3A9E79,0x6C74B31E,0x6F672F4D,0x7F0FF7C8];
function hex8(v) {
  var s = (v >>> 0).toString(16);
  while (s.length < 8) s = '0' + s;
  return s;
}
Interceptor.attach(base.add(0x7d5009 - 0x400000), {
  onEnter: function () {
    var id = null;
    try { id = this.context.esp.add(0xdc).readU32() >>> 0; } catch (e) {}
    var bt = [];
    try {
      var fr = Thread.backtrace(this.context, Backtracer.FUZZY);
      for (var i = 0; i < fr.length && i < 8; i++) {
        try { bt.push(fr[i].sub(base).toInt32() >>> 0); } catch (e2) {}
      }
    } catch (e3) {}
    send({ msgid: (id === null ? null : hex8(id)),
           known: (id === null ? null : KNOWN.indexOf(id) >= 0),
           bt: bt });
  }
});
send({ boot: 'hooked 0x7d5009' });
'''


def find_pid() -> int | None:
    try:
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True)
        txt = out.stdout.decode("mbcs", "replace")
        for line in txt.splitlines():
            if MOD.lower() in line.lower():
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2 and parts[1].isdigit():
                    return int(parts[1])
    except Exception:
        pass
    return None


def attach_and_hold(pid: int, fh) -> None:
    sess = frida.attach(pid)
    sc = sess.create_script(JS)

    def on_msg(m, d):
        payload = m.get("payload")
        line = json.dumps(payload, ensure_ascii=False) if isinstance(payload, dict) else str(m)
        fh.write(time.strftime("%H:%M:%S ") + line + "\n")
        fh.flush()
        print(line, flush=True)

    sc.on("message", on_msg)
    fh.write("\n===== hook_msgid pid=%d %s =====\n" % (pid, time.strftime("%H:%M:%S")))
    fh.flush()
    sc.load()
    print("[+] hooked pid=%d" % pid, flush=True)
    while True:
        time.sleep(1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pid", nargs="?", type=lambda s: int(s, 0))
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--delay", type=float, default=20.0,
                    help="--follow 发现进程后再等几秒才注入（太早注入会触发壳的反调试）")
    a = ap.parse_args()

    fh = LOG.open("a", encoding="utf-8")
    try:
        if not a.follow:
            if not a.pid:
                print("usage: hook_msgid.py <pid> | --follow", file=sys.stderr)
                return 2
            attach_and_hold(a.pid, fh)
            return 0

        print("[i] waiting for %s ..." % MOD, flush=True)
        cur = None
        while True:
            pid = find_pid()
            if pid and pid != cur:
                cur = pid
                print("[i] found pid=%d, waiting %.0fs before attach ..." % (pid, a.delay),
                      flush=True)
                time.sleep(a.delay)   # 让客户端先过完壳的启动自检
                try:
                    attach_and_hold(pid, fh)
                except Exception as e:  # 客户端退出 / 还没准备好
                    print("[-] attach %d failed: %r" % (pid, e), flush=True)
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        fh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
