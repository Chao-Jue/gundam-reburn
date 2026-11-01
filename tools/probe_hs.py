"""定位"16 字节登录包"的产出者。

思路：`0xbeb3a3` 处调用 `RingWrite(buf, [Socket+0x270]>>3)`，
而 buf 是 `[Socket+0x274]` 对象 `vtable[+0x10]` 这个方法填的：
    0xbeb35a  mov ecx,[esi+0x274]
    0xbeb35c  mov edx,[ecx]
    0xbeb35f  lea eax,[esp+0x68]
    0xbeb363  push eax
    0xbeb364  call edx            ; vtable+0x10
本脚本在每次 RingWrite(len==16) 时把
  Socket 指针 / [Socket+0x274] / 它的 vtable / vtable 前 8 项 / 对象内存
全部 dump 出来，并**顺手给 vtable+0x10 那个方法挂上钩**，
下次登录就能看到它的入参（buf）和返回后的内容。

用法：python tools/probe_hs.py --pid <pid> --seconds 1800
日志：server/probe_hs.log
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
LOG = os.path.join(ROOT, 'server', 'probe_hs.log')
MOD = 'GundamOnline_CHINA.exe'

JS = r'''
'use strict';
const BASE = 0x400000;
const mod = Process.getModuleByName('GundamOnline_CHINA.exe');
function logEv(o) { try { o.t = 1; send(o); } catch (e) {} }
function hx(n) { return '0x' + (n >>> 0).toString(16); }
function hexOf(p, n) {
  try { if (!p || p.isNull() || n <= 0) return null;
    const b = new Uint8Array(p.readByteArray(Math.min(n, 512)));
    return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  } catch (e) { return 'ERR:' + String(e); }
}
function safePtr(p, off) { try { return p.add(off).readPointer(); } catch (e) { return null; } }
function safeU32(p, off) { try { return p.add(off).readU32(); } catch (e) { return null; } }

const hooked = {};
function hookMethod(addr, tag) {
  if (!addr || addr.isNull()) return false;
  const key = addr.toString();
  if (hooked[key]) return true;
  hooked[key] = 1;
  try {
    Interceptor.attach(addr, {
      onEnter(a) {
        this.buf = a[0];
        logEv({ ev: 'meth.enter', tag: tag, at: addr.toString(),
                ecx: this.context.ecx.toString(), arg0: a[0].toString(),
                pre: hexOf(a[0], 32) });
      },
      onLeave(r) {
        logEv({ ev: 'meth.leave', tag: tag, ret: (r.toInt32 ? r.toInt32() : null),
                post: hexOf(this.buf, 32) });
      },
    });
    logEv({ ev: 'meth.hooked', tag: tag, at: addr.toString() });
    return true;
  } catch (e) {
    logEv({ ev: 'meth.fail', tag: tag, at: addr.toString(), err: String(e) });
    return false;
  }
}

Interceptor.attach(mod.base.add(0xc034f0 - BASE), {
  onEnter(a) {
    let len = 0;
    try { len = a[1].toInt32(); } catch (e) { return; }
    if (len !== 16) return;
    const ring = this.context.ecx;
    const sock = ring.sub(0x1f8);
    const obj = safePtr(sock, 0x274);
    const info = {
      ev: 'hs16', hex: hexOf(a[0], 16),
      sock: sock.toString(), bits: safeU32(sock, 0x270),
      state: safeU32(sock, 0x280), sockfd: safeU32(sock, 0x48),
    };
    if (obj && !obj.isNull()) {
      info.obj = obj.toString();
      const vt = safePtr(obj, 0);
      info.vt = vt ? vt.toString() : null;
      if (vt) {
        info.slots = [];
        for (let o = 0; o < 0x20; o += 4) {
          const s = safePtr(vt, o);
          info.slots.push(s ? s.toString() : null);
        }
        info.objmem = hexOf(obj, 0x60);
        hookMethod(safePtr(vt, 0x10), 'vt+0x10');
      }
    } else {
      info.obj = null;
    }
    logEv(info);
  },
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
    ap.add_argument('--seconds', type=int, default=1800)
    a = ap.parse_args()
    pid = a.pid or find_pid()
    if not pid:
        print('客户端没在跑')
        return 1
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    f = open(LOG, 'a', encoding='utf-8')
    f.write('\n===== probe_hs pid=%d %s =====\n' % (pid, time.strftime('%H:%M:%S')))
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
