"""挂客户端**模块内部**的收发路径 + 验证 hook 是否真的写入内存。

与 attach_net.py 的区别：
  1. 每个 hook 装完后**回读函数首字节**，日志里能看到是否出现 `e9`（frida 的 5 字节相对跳转），
     这样能立刻区分"没挂上"和"挂上了但没被调用"。
  2. RingWrite 记录更长的调用栈（20 帧），用于向上追到"谁写入了这 16 字节"。
  3. 日志写 server/hook_net2.log。

用法：python tools/hook_net2.py --seconds 2400
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
LOG = os.path.join(ROOT, 'server', 'hook_net2.log')
MOD = 'GundamOnline_CHINA.exe'

JS = r'''
'use strict';
const MODNAME = 'GundamOnline_CHINA.exe';
const BASE = 0x400000;
const mod = Process.getModuleByName(MODNAME);

function logEv(o) { try { o.t = Date.now(); send(o); } catch (e) {} }
function hx(n) { return '0x' + (n >>> 0).toString(16); }
function hexOf(p, n) {
  try {
    if (!p || p.isNull() || !n || n <= 0) return null;
    const b = new Uint8Array(p.readByteArray(Math.min(n, 1024)));
    return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  } catch (e) { return null; }
}
function sym(a) {
  try {
    const m = Process.findModuleByAddress(a);
    if (m) return m.name + '+0x' + a.sub(m.base).toString(16);
    return hx(a);
  } catch (e) { return hx(a); }
}
function btAcc(ctx, n) {
  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, n || 12).map(sym); }
  catch (e) { return ['bt-err:' + String(e)]; }
}

function hookOff(off, name, spec) {
  const addr = mod.base.add(off - BASE);
  const before = hexOf(addr, 8);
  try {
    Interceptor.attach(addr, {
      onEnter(a) { try { spec.enter.call(this, a); } catch (e) { logEv({ ev: 'err', tag: name, err: String(e) }); } },
      onLeave(r) { try { if (spec.leave) spec.leave.call(this, r); } catch (e) {} },
    });
    logEv({ ev: 'hooked', name: name, at: addr.toString(), pre: before, post: hexOf(addr, 8) });
  } catch (e) {
    logEv({ ev: 'hook-fail', name: name, err: String(e) });
  }
}

hookOff(0xc034f0, 'RingWrite', {
  enter(a) {
    const len = a[1].toInt32();
    if (len <= 0 || len > 8192) return;
    logEv({ ev: 'ring.write', thisp: this.context.ecx.toString(), len: len,
            hex: hexOf(a[0], len), acc: btAcc(this.context, 20) });
  },
});

hookOff(0xbf9410, 'FlushSend', {
  enter(a) { this.ctx = this.context; },
  leave(r) { logEv({ ev: 'flush.ret', ret: (r.toInt32 ? r.toInt32() : null), acc: btAcc(this.ctx, 14) }); },
});

hookOff(0xc03dc0, 'SockSend', {
  enter(a) {
    const len = a[1].toInt32();
    if (len < 0 || len > 8192) return;
    logEv({ ev: 'sock.send', len: len, hex: len ? hexOf(a[0], len) : null, acc: btAcc(this.context, 16) });
  },
});

hookOff(0xc03d10, 'SockRecv', {
  enter(a) { this.buf = a[0]; this.want = a[1].toInt32(); },
  leave(r) {
    let n = 0;
    try { n = r.toInt32(); } catch (e) {}
    if (n > 0) logEv({ ev: 'sock.recv', got: n, hex: hexOf(this.buf, n) });
  },
});

hookOff(0xbf8a00, 'OnRead', {
  enter(a) { logEv({ ev: 'onread', acc: btAcc(this.context, 12) }); },
});

logEv({ ev: 'ready' });
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
    ap.add_argument('--seconds', type=int, default=2400)
    a = ap.parse_args()
    pid = a.pid or find_pid()
    if not pid:
        print('客户端没在跑')
        return 1
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    f = open(LOG, 'a', encoding='utf-8')
    f.write('\n===== hook_net2 pid=%d %s =====\n' % (pid, time.strftime('%H:%M:%S')))
    f.flush()
    session = frida.attach(pid)

    def on_msg(msg, data):
        if msg.get('type') == 'error':
            line = '[JS-ERR] ' + str(msg.get('description'))
        else:
            p = msg.get('payload')
            if isinstance(p, dict):
                p.pop('t', None)
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
        alive = True
        while time.time() - t0 < a.seconds and alive:
            time.sleep(1)
            alive = find_pid() == pid
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
