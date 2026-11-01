"""精确栈版网络 hook：抓 send/WSASend/connect 的**精确返回地址** + EBP 链 + 栈快照。

与 attach_ws2.py 的区别：
  - 记录 this.returnAddress（精确，不是模糊回溯）
  - 记录 Backtracer.ACCURATE 结果
  - 手动走 EBP 链（客户端是 /Oy- 编译，帧指针完整）
  - 把 esp 起的 0x100 字节按 dword 打出来，离线自己核对

用法：python tools/attach_ws2b.py --seconds 1800
日志：server/attach_ws2b.log
"""
import argparse
import json
import os
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LOG = os.path.join(ROOT, 'server', 'attach_ws2b.log')

JS = r'''
'use strict';
function logEv(o) { try { o.t = Date.now(); send(o); } catch (e) {} }
function hx(n) { return '0x' + (n >>> 0).toString(16); }
function hexOf(p, n) {
  try {
    if (!p || p.isNull() || !n || n <= 0) return null;
    const b = new Uint8Array(p.readByteArray(Math.min(n, 512)));
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
  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, n || 16).map(sym); }
  catch (e) { return ['bt-err:' + String(e)]; }
}
// 手动走 EBP 链：ebp -> [ebp] 上一帧 ebp，[ebp+4] 返回地址
function ebpChain(ctx, n) {
  const out = [];
  try {
    let ebp = ctx.ebp;
    for (let i = 0; i < (n || 16); i++) {
      if (!ebp || ebp < 0x1000) break;
      const prev = ptr(ebp).readPointer();
      const ret = ptr(ebp).add(4).readPointer();
      out.push(sym(ret));
      if (prev.compare(ebp) >= 0) break;
      ebp = prev;
    }
  } catch (e) { out.push('ebp-err:' + String(e)); }
  return out;
}
function stackDump(ctx, words) {
  const out = [];
  try {
    for (let i = 0; i < (words || 64); i++) out.push(ptr(ctx.esp).add(i * 4).readU32());
  } catch (e) {}
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

let mod = Process.getModuleByName('ws2_32.dll');
function mk(name, spec) {
  let a;
  try { a = mod.getExportByName(name); } catch (e) { logEv({ ev: 'noexport', name: name }); return; }
  Interceptor.attach(a, {
    onEnter(args) {
      try { spec.enter.call(this, args); } catch (e) { logEv({ ev: 'err', tag: name, err: String(e) }); }
    },
    onLeave(r) { try { if (spec.leave) spec.leave.call(this, r); } catch (e) {} },
  });
  logEv({ ev: 'hooked', name: name });
}

mk('send', {
  enter(a) {
    const n = a[2].toInt32();
    if (n <= 0 || n > 1024) return;
    logEv({ ev: 'send', sock: a[0].toInt32(), len: n, hex: hexOf(a[1], n),
            ret: sym(this.returnAddress),
            acc: btAcc(this.context, 14), ebp: ebpChain(this.context, 14),
            esp: hx(this.context.esp), stk: stackDump(this.context, 48) });
  },
});
mk('WSASend', {
  enter(a) {
    const cnt = a[2].toInt32();
    if (cnt < 1 || cnt > 4) return;
    const wb = a[1];
    const len = wb.readU32();
    if (len <= 0 || len > 1024) return;
    logEv({ ev: 'WSASend', sock: a[0].toInt32(), len: len, hex: hexOf(wb.add(4).readPointer(), len),
            ret: sym(this.returnAddress),
            acc: btAcc(this.context, 14), ebp: ebpChain(this.context, 14) });
  },
});
mk('connect', {
  enter(a) {
    logEv({ ev: 'connect', target: sockaddrStr(a[1]), sock: a[0].toInt32(),
            ret: sym(this.returnAddress),
            acc: btAcc(this.context, 16), ebp: ebpChain(this.context, 16) });
  },
  leave(r) { logEv({ ev: 'connect.ret', ret: r.toInt32() }); },
});
mk('closesocket', {
  enter(a) { logEv({ ev: 'closesocket', sock: a[0].toInt32(), ret: sym(this.returnAddress), ebp: ebpChain(this.context, 10) }); },
});
logEv({ ev: 'ready' });
'''


def find_pid():
    out = os.popen('tasklist /FI "IMAGENAME eq GundamOnline_CHINA.exe" /FO CSV /NH').read()
    for line in out.splitlines():
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
        print('没找到客户端')
        return 1
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    f = open(LOG, 'a', encoding='utf-8')
    f.write('\n===== attach2 pid=%d %s =====\n' % (pid, time.strftime('%H:%M:%S')))
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
    print('已挂上 pid=%d -> %s' % (pid, LOG))
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
