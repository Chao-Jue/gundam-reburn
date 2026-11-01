#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""数据表下载探针：定位「0x5290 回了却不往下要第三张表」到底断在哪一步。

只挂游戏进程内部的几个函数，**不改任何返回值**：
    0xAB09B6  0x5290 响应处理入口（CGVOProtoLounge）
    0xAB0B52  「消费长度 == 消息结尾」的检查（不相等就 call [vtable+0x64] 中止）
    0x544790  处理一条下载完成的文件（整个函数带 SEH 帧，异常会被吞掉）
    0xA46480  正文 UTF-8 → UTF-16（失败返回 0x80100000，调用点会直接 bail）
    0x544922  文件序号 1（msma/msma_weapon_set.csv）的分支
    0x544DD7  把节点从队列摘掉（= 成功推进）
    0x544E07  清理退出（失败 / 异常都汇到这里）

用法（客户端已经在登录界面时）：
    python tools/hook_datadl.py            # 自动找进程
    python tools/hook_datadl.py 39856      # 指定 pid

日志：server/datadl.log
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
LOG = ROOT / "server" / "datadl.log"
MOD = "GundamOnline_CHINA"

JS = r'''
var base = Process.getModuleByName('GundamOnline_CHINA.exe').base;
function A(va) { return base.add(va - 0x400000); }
function u32(p) { try { return p.readU32() >>> 0; } catch (e) { return null; } }
function ptrAt(p) { try { return p.readPointer(); } catch (e) { return null; } }
function hex(v) { return v === null ? null : '0x' + (v >>> 0).toString(16); }
function hexOf(p, n) {
  try {
    var b = new Uint8Array(p.readByteArray(n));
    var s = '';
    for (var i = 0; i < b.length; i++) { s += (b[i] < 16 ? '0' : '') + b[i].toString(16); }
    return s;
  } catch (e) { return null; }
}
function hook(va, name, enter, leave) {
  try {
    Interceptor.attach(A(va), {
      onEnter: function (args) { try { if (enter) enter.call(this, args); } catch (e) { send({err: name + ':in', m: String(e)}); } },
      onLeave: function (ret) { try { if (leave) leave.call(this, ret); } catch (e) { send({err: name + ':out', m: String(e)}); } }
    });
    send({ installed: name });
  } catch (e) { send({ err: 'hook:' + name, m: String(e) }); }
}

hook(0xAB09B6, 'recv5290', function () { send({ ev: 'recv5290' }); });

hook(0xAB0B52, 'endcheck', function () {
  var sp = this.context.esp;
  send({ ev: 'endcheck', cur: hex(u32(sp.add(0x14))), end: hex(u32(sp.add(0x18))) });
});

hook(0x544790, 'dlproc', function () {
  var th = this.context.ecx;
  var st = { ev: 'dlproc', th: th.toString() };
  try {
    var sentinel = ptrAt(th.add(8));
    st.sentinel = sentinel ? sentinel.toString() : null;
    var first = sentinel ? ptrAt(sentinel) : null;
    st.first = first ? first.toString() : null;
    if (first && sentinel && !first.equals(sentinel)) {
      st.idx = hex(u32(first.add(0xc)));
      st.flag = hex(u32(first.add(0x10)));
    }
  } catch (e) { st.e = String(e); }
  send(st);
}, function (ret) { send({ ev: 'dlproc.ret', ret: hex(ret.toInt32()) }); });

hook(0xA46480, 'text2wide', function (args) {
  var s = args[1];
  var st = { ev: 'text2wide' };
  try {
    var d = ptrAt(s.add(4));
    var len = u32(s.add(8));
    st.len = len;
    st.head = d ? hexOf(d, Math.min(len || 0, 16)) : null;
  } catch (e) { st.e = String(e); }
  send(st);
}, function (ret) { send({ ev: 'text2wide.ret', ret: hex(ret.toInt32()) }); });

hook(0x544922, 'case1', function () { send({ ev: 'case1' }); });
hook(0x544DD7, 'advance', function () { send({ ev: 'advance' }); });
hook(0x544E07, 'bail', function () { send({ ev: 'bail' }); });

send({ boot: 'probes installed', base: base.toString() });
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
    fh.write("\n===== hook_datadl pid=%d %s =====\n" % (pid, time.strftime("%Y-%m-%d %H:%M:%S")))
    fh.flush()
    sc.load()
    print("[+] hooked pid=%d" % pid, flush=True)
    while True:
        time.sleep(1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pid", nargs="?", type=lambda s: int(s, 0))
    a = ap.parse_args()

    pid = a.pid or find_pid()
    if not pid:
        print("[-] 没找到 GundamOnline_CHINA.exe，先把客户端开到登录界面", file=sys.stderr)
        return 2
    fh = LOG.open("a", encoding="utf-8")
    try:
        attach_and_hold(pid, fh)
    except KeyboardInterrupt:
        pass
    finally:
        fh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
