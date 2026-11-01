"""对已经在跑的客户端做"热挂"：只装网络发包 hook，抓 16 字节登录包的调用栈。

用法（管理员）：
    python tools/attach_ws2.py            # 自动找 GundamOnline_CHINA.exe
    python tools/attach_ws2.py --pid 1234
    python tools/attach_ws2.py --seconds 600

日志：server/attach_ws2.log
"""
import argparse
import json
import os
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LOG = os.path.join(ROOT, 'server', 'attach_ws2.log')

JS = r'''
'use strict';
const LOGF = null;
function now() { return Date.now(); }
function logEv(o) { try { o.t = now(); send(o); } catch (e) {} }
function hx(n) { return '0x' + (n >>> 0).toString(16); }
function hexOf(p, n, max) {
  try {
    if (!p || p.isNull() || !n || n <= 0) return null;
    const b = new Uint8Array(p.readByteArray(Math.min(n, max || 512)));
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
function btOf(ctx, depth) {
  const out = [];
  try {
    const frames = Thread.backtrace(ctx, Backtracer.FUZZY).slice(0, depth || 14);
    for (const a of frames) out.push(sym(a));
  } catch (e) { out.push('bt-err:' + String(e)); }
  return out;
}
function sockaddrStr(p) {
  try {
    if (!p || p.isNull()) return null;
    if (p.readU16() !== 2) return 'family=' + p.readU16();
    const raw = p.add(2).readU16();
    const port = ((raw & 0xff) << 8) | (raw >> 8);
    const ip = Array.from(new Uint8Array(p.add(4).readByteArray(4))).join('.');
    return ip + ':' + port;
  } catch (e) { return null; }
}

function install() {
  let mod;
  try { mod = Process.getModuleByName('ws2_32.dll'); } catch (e) {
    logEv({ ev: 'nomod', name: 'ws2_32.dll' }); return;
  }
  const mk = (name, spec) => {
    let a;
    try { a = mod.getExportByName(name); } catch (e) { logEv({ ev: 'noexport', name: name }); return; }
    Interceptor.attach(a, {
      onEnter(args) {
        try { spec.enter.call(this, args); } catch (e) { logEv({ ev: 'err', tag: name, err: String(e) }); }
      },
      onLeave(r) {
        try { if (spec.leave) spec.leave.call(this, r); } catch (e) {}
      },
    });
    logEv({ ev: 'hooked', name: name, addr: a.toString() });
  };

  mk('WSASend', {
    enter(a) {
      const cnt = a[2].toInt32();
      const wsabuf = a[1];
      const parts = [];
      let total = 0;
      for (let i = 0; i < Math.min(cnt, 4); i++) {
        const len = wsabuf.add(i * 8).readU32();
        const buf = wsabuf.add(i * 8 + 4).readPointer();
        total += len;
        parts.push({ len: len, buf: buf.toString(), hex: hexOf(buf, len, 256) });
      }
      logEv({ ev: 'WSASend', sock: a[0].toInt32(), cnt: cnt, total: total,
              parts: parts, bt: btOf(this.context, 14) });
    },
  });
  mk('send', {
    enter(a) {
      const n = a[2].toInt32();
      logEv({ ev: 'send', sock: a[0].toInt32(), len: n, hex: hexOf(a[1], n, 256),
              bt: btOf(this.context, 14) });
    },
  });
  mk('WSASendTo', {
    enter(a) {
      const cnt = a[2].toInt32();
      const wsabuf = a[1];
      const len = wsabuf.readU32();
      const buf = wsabuf.add(4).readPointer();
      logEv({ ev: 'WSASendTo', sock: a[0].toInt32(), cnt: cnt, len: len,
              hex: hexOf(buf, len, 256), to: sockaddrStr(a[5]), bt: btOf(this.context, 14) });
    },
  });
  mk('connect', {
    enter(a) { logEv({ ev: 'connect', target: sockaddrStr(a[1]), sock: a[0].toInt32(), bt: btOf(this.context, 14) }); },
    leave(r) { logEv({ ev: 'connect.ret', ret: r.toInt32() }); },
  });
  mk('WSAConnect', {
    enter(a) { logEv({ ev: 'WSAConnect', target: sockaddrStr(a[1]), sock: a[0].toInt32(), bt: btOf(this.context, 14) }); },
    leave(r) { logEv({ ev: 'WSAConnect.ret', ret: r.toInt32() }); },
  });
  mk('closesocket', {
    enter(a) { logEv({ ev: 'closesocket', sock: a[0].toInt32(), bt: btOf(this.context, 8) }); },
  });
  // 顺带看谁在读响应（如果服务端将来回了包）
  mk('WSARecv', {
    enter(a) {
      const wsabuf = a[1];
      logEv({ ev: 'WSARecv.enter', sock: a[0].toInt32(),
              want: wsabuf.readU32(), bt: btOf(this.context, 12) });
    },
    leave(r) { logEv({ ev: 'WSARecv.ret', ret: r.toInt32() }); },
  });
  logEv({ ev: 'ready' });
}

install();
'''

def find_pid():
    try:
        out = os.popen('tasklist /FI "IMAGENAME eq GundamOnline_CHINA.exe" /FO CSV /NH').read()
    except Exception:
        out = ''
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=int)
    ap.add_argument('--seconds', type=int, default=900)
    args = ap.parse_args()

    pid = args.pid or find_pid()
    if not pid:
        print('没找到 GundamOnline_CHINA.exe')
        return 1

    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    f = open(LOG, 'a', encoding='utf-8')
    f.write('\n===== attach pid=%d %s =====\n' % (pid, time.strftime('%H:%M:%S')))
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
        print(line[:400])

    script = session.create_script(JS)
    script.on('message', on_msg)
    script.load()
    print('已挂上 pid=%d，日志 -> %s' % (pid, LOG))
    print('现在去客户端点「登录」，然后回来按 Ctrl+C 结束。')

    t0 = time.time()
    try:
        while time.time() - t0 < args.seconds:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            session.detach()
        except Exception:
            pass
        f.close()
        print('脱离完成')
    return 0


if __name__ == '__main__':
    sys.exit(main())
