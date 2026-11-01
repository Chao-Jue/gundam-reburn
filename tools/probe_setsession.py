"""追问"那 16 字节是谁写进 RSA 上下文的"。

已知：
  vtable 0xe642b8，类的 RTTI 名 `.?AU?$RSAContext@$0IA@@ivce@@`（$0IA = 128 字节 / 1024 位）
  对象字段：+0x04 = 0x80(128)，+0x08 = 0x00010001(e=65537)，+0x18 = 16 字节"会话量"，
            +0x28 起是 128 字节模数 n
  虚表：+0x10 = 读 +0x18（返回 16 字节），+0x14 = 写 +0x18
→ 所以 16 字节不是算出来的，是**被提前写进去的**。本脚本盯死这个 setter（0xbdc580），
  记录调用者栈 + 写入值，从而找到"生成这 16 字节"的那段代码。

用法：python tools/probe_setsession.py --pid <pid> --seconds 1800
日志：server/probe_setsession.log
"""
import argparse
import json
import os
import subprocess
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LOG = os.path.join(ROOT, 'server', 'probe_setsession.log')
MOD = 'GundamOnline_CHINA.exe'
VT = 0xe642b8

JS = r'''
'use strict';
const BASE = 0x400000;
const VT = 0xe642b8;
const mod = Process.getModuleByName('GundamOnline_CHINA.exe');
function logEv(o) { try { o.q = 1; send(o); } catch (e) {} }
function hx(n) { return '0x' + (n >>> 0).toString(16); }
function hexOf(p, n) {
  try { if (!p || p.isNull() || n <= 0) return null;
    const b = new Uint8Array(p.readByteArray(Math.min(n, 1024)));
    return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  } catch (e) { return 'ERR'; }
}
function sym(a) {
  try { const m = Process.findModuleByAddress(a);
    return m ? m.name + '+0x' + a.sub(m.base).toString(16) : hx(a);
  } catch (e) { return hx(a); }
}
function btAcc(ctx, n) {
  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, n || 16).map(sym); }
  catch (e) { return ['bt-err']; }
}

// ---- setter: 0xbdc580 (vt+0x14)，thiscall，arg0 = 源指针 ----
Interceptor.attach(mod.base.add(0xbdc580 - BASE), {
  onEnter(a) {
    const src = a[0];
    logEv({ ev: 'set16', obj: this.context.ecx.toString(),
            val: hexOf(src, 16), acc: btAcc(this.context, 18) });
  },
});

// ---- getter: 0xbdc540 (vt+0x10)，记录谁在读 ----
Interceptor.attach(mod.base.add(0xbdc540 - BASE), {
  onEnter(a) { this.dst = a[0]; this.ctx = this.context; },
  onLeave(r) {
    logEv({ ev: 'get16', dst: this.dst.toString(), val: hexOf(this.dst, 16),
            acc: btAcc(this.ctx, 14) });
  },
});

// ---- RingWrite：16 字节时把整个对象 dump 出来 ----
Interceptor.attach(mod.base.add(0xc034f0 - BASE), {
  onEnter(a) {
    let len = 0;
    try { len = a[1].toInt32(); } catch (e) { return; }
    if (len !== 16) return;
    const sock = this.context.ecx.sub(0x1f8);
    let obj = null, info = { ev: 'dump16', hex: hexOf(a[0], 16),
                             sock: sock.toString(), bits: null, obj: null };
    try { info.bits = sock.add(0x270).readU32(); } catch (e) {}
    try { obj = sock.add(0x274).readPointer(); } catch (e) {}
    if (obj && !obj.isNull()) {
      info.obj = obj.toString();
      try { info.vt = obj.readPointer().toString(); } catch (e) {}
      info.objmem = hexOf(obj, 0x120);
    }
    logEv(info);
  },
});

logEv({ ev: 'ready', vt: '0x' + VT.toString(16) });
'''


def find_pid():
    out = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq ' + MOD, '/FO', 'CSV', '/NH'],
                         capture_output=True)
    txt = out.stdout.decode('mbcs', 'replace')
    for line in txt.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=int)
    ap.add_argument('--seconds', type=int, default=1800)
    a = ap.parse_args()
    pid = a.pid or find_pid()
    if not pid:
        print('客户端没在跑')
        return 1
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    f = open(LOG, 'a', encoding='utf-8')
    f.write('\n===== probe_setsession pid=%d %s =====\n' % (pid, time.strftime('%H:%M:%S')))
    f.flush()
    session = frida.attach(pid)

    def on_msg(msg, data):
        if msg.get('type') == 'error':
            line = '[JS-ERR] ' + str(msg.get('description'))
        else:
            p = msg.get('payload')
            if isinstance(p, dict):
                p.pop('q', None)
                line = json.dumps(p, ensure_ascii=False)
            else:
                line = str(p)
        f.write(time.strftime('%H:%M:%S ') + line + '\n')
        f.flush()

    script = session.create_script(JS)
    script.on('message', on_msg)
    script.load()
    print('挂上 pid=%d -> %s' % (pid, LOG))
    t0 = time.time()
    try:
        while time.time() - t0 < a.seconds and find_pid() == pid:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            session.detach()
        except Exception:
            pass
        f.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
