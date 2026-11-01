"""挂客户端**模块内部**的收发路径（不是 Win32 API），抓明文/密文与调用链。

已定位的函数（VA，模块基址 0x400000）：
  0xc034f0  RingBuffer::Write(data, len)   —— 所有待发字节都从这里进环形缓冲
  0xbf9410  Socket::FlushSendBuffer()      —— 从环形缓冲取数据 -> send()
  0xc03dc0  Socket::Send(buf, len, pOut)   —— 薄包装，内部 call send
  0xc03d10  Socket::Recv(buf, len)         —— 薄包装，内部 call recv
  0xbf8a00  Socket::OnRead()               —— 收包泵：Recv 0x10000 字节后交给上层
  0xbfcf70  Connect 包装

用法：python tools/attach_net.py --seconds 2400
日志：server/attach_net.log
"""
import argparse
import json
import os
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LOG = os.path.join(ROOT, 'server', 'attach_net.log')
MOD = 'GundamOnline_CHINA.exe'
BASE = 0x400000

JS = r'''
'use strict';
const MODNAME = 'GundamOnline_CHINA.exe';
const BASE = 0x400000;
function logEv(o) { try { o.t = Date.now(); send(o); } catch (e) {} }
function hx(n) { return '0x' + (n >>> 0).toString(16); }
function hexOf(p, n) {
  try {
    if (!p || p.isNull() || !n || n <= 0) return null;
    const b = new Uint8Array(p.readByteArray(Math.min(n, 2048)));
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

const mod = Process.getModuleByName(MODNAME);
if (mod.base.toUInt32() !== BASE) logEv({ ev: 'warn-base', base: mod.base.toString() });

function hookOff(off, name, spec) {
  const addr = mod.base.add(off - BASE);
  try {
    Interceptor.attach(addr, {
      onEnter(a) { try { spec.enter.call(this, a); } catch (e) { logEv({ ev: 'err', tag: name, err: String(e) }); } },
      onLeave(r) { try { if (spec.leave) spec.leave.call(this, r); } catch (e) {} },
    });
    logEv({ ev: 'hooked', name: name, at: addr.toString() });
  } catch (e) {
    logEv({ ev: 'hook-fail', name: name, err: String(e) });
  }
}

// RingBuffer::Write(const void* data, int len)  —— thiscall，ecx=this(RingBuffer*)
hookOff(0xc034f0, 'RingWrite', {
  enter(a) {
    const len = a[1].toInt32();
    if (len <= 0 || len > 4096) return;
    logEv({ ev: 'ring.write', thisp: this.context.ecx.toString(), len: len,
            hex: hexOf(a[0], len), acc: btAcc(this.context, 10) });
  },
});

// Socket::FlushSendBuffer()
hookOff(0xbf9410, 'FlushSend', {
  enter(a) { this.ctx = this.context; },
  leave(r) { logEv({ ev: 'flush.ret', ret: (r.toInt32 ? r.toInt32() : null), acc: btAcc(this.ctx, 10) }); },
});

// Socket::Send(buf, len, pOut) —— thiscall
hookOff(0xc03dc0, 'SockSend', {
  enter(a) {
    const len = a[1].toInt32();
    if (len < 0 || len > 4096) return;
    logEv({ ev: 'sock.send', len: len, hex: len ? hexOf(a[0], len) : null, acc: btAcc(this.context, 12) });
  },
});

// Socket::Recv(buf, len) —— thiscall
hookOff(0xc03d10, 'SockRecv', {
  enter(a) { this.buf = a[0]; this.want = a[1].toInt32(); },
  leave(r) {
    const n = r.toInt32();
    if (n > 0) logEv({ ev: 'sock.recv', got: n, hex: hexOf(this.buf, n) });
  },
});

// Socket::OnRead()
hookOff(0xbf8a00, 'OnRead', {
  enter(a) { logEv({ ev: 'onread', acc: btAcc(this.context, 10) }); },
});

logEv({ ev: 'ready' });
'''


def find_pid():
    import subprocess
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
    f.write('\n===== attach_net pid=%d %s =====\n' % (pid, time.strftime('%H:%M:%S')))
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
        while time.time() - t0 < a.seconds:
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
