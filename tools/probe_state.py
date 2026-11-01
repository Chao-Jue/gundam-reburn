"""实时追踪 Socket 握手状态机 [Socket+0x280] 的每一步。

已逆出的状态迁移（全部是 `mov dword [esi+0x280], imm`）：
  0xbeb310 -> 4      1->connect 失败分支
  0xbeb45a -> 3      ★ 发完 16 字节握手包，转入"等 32 字节回应"
  0xbeb590 -> 4      另一条失败分支
  0xbeb6da -> 3      flush 完成后的等价迁移
  0xbefafe -> 2      构造 RSAContext(128)，准备发握手
  0xbefc5a -> 5      收到 16 字节分支（state 4）走通
  0xbefca1 -> 6      ★ 就绪（此后才开始跑正常协议包）
  0xbefe0a -> 5      state 4 的另一条
  0xbefe51 -> 6

另挂关键节点：
  0xbedc70   state 3 收到 32 字节后建立会话密钥
  0xbed980   state 5 生成 16 字节
  0xbf8820   取"可读字节数"（能看出服务端到底回了多少）
  0xbdc580   把服务端 16 字节写进 RSAContext
  RingWrite  所有待发字节

用法：python tools/probe_state.py --pid <pid> --seconds 1800
日志：server/probe_state.log
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
LOG = os.path.join(ROOT, 'server', 'probe_state.log')
MOD = 'GundamOnline_CHINA.exe'

STATE_SETTERS = {
    0xbeb310: 4,
    0xbeb45a: 3,
    0xbeb590: 4,
    0xbeb6da: 3,
    0xbefafe: 2,
    0xbefc5a: 5,
    0xbefca1: 6,
    0xbefe0a: 5,
    0xbefe51: 6,
}

JS = r'''
'use strict';
const BASE = 0x400000;
const mod = Process.getModuleByName('GundamOnline_CHINA.exe');
const SETTERS = __SETTERS__;
function logEv(o) { try { o.q = 1; send(o); } catch (e) {} }
function hx(n) { return '0x' + (n >>> 0).toString(16); }
function hexOf(p, n) {
  try { if (!p || p.isNull() || n <= 0) return null;
    const b = new Uint8Array(p.readByteArray(Math.min(n, 512)));
    return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  } catch (e) { return 'ERR'; }
}
function sym(a) {
  try { const m = Process.findModuleByAddress(a);
    return m ? m.name + '+0x' + a.sub(m.base).toString(16) : hx(a);
  } catch (e) { return hx(a); }
}
function btAcc(ctx, n) {
  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, n || 10).map(sym); }
  catch (e) { return ['bt-err']; }
}
function at(off) { return mod.base.add(off - BASE); }

// ---- 状态迁移 ----
Object.keys(SETTERS).forEach(function (off) {
  Interceptor.attach(at(parseInt(off, 10)), {
    onEnter() {
      const ctx = this.context;
      logEv({ ev: 'state', to: SETTERS[off], at: '0x' + parseInt(off, 10).toString(16),
              sock: hx(ctx.esi) });
    },
  });
});

// ---- state3 收到 32 字节后建会话密钥 ----
Interceptor.attach(at(0xbedc70), {
  onEnter() { logEv({ ev: 'keybuild32', sock: hx(this.context.ecx), bt: btAcc(this.context, 8) }); },
});

// ---- state5 生成 16 字节 ----
Interceptor.attach(at(0xbed980), {
  onEnter() { logEv({ ev: 'gen16', sock: hx(this.context.ecx) }); },
});

// ---- 可读字节数 ----
Interceptor.attach(at(0xbf8820), {
  onEnter(a) { this.out = a[0]; this.ctx = this.context; },
  onLeave(r) {
    let n = null;
    try { n = this.out.readU32(); } catch (e) {}
    logEv({ ev: 'avail', n: n, ptr: hx(r), peek: hexOf(r, Math.min(n || 0, 64)) });
  },
});

// ---- 服务端 16 字节写入 RSA 上下文 ----
Interceptor.attach(at(0xbdc580), {
  onEnter(a) { logEv({ ev: 'set16', val: hexOf(a[0], 16) }); },
});

// ---- 所有待发字节 ----
Interceptor.attach(at(0xc034f0), {
  onEnter(a) {
    let len = 0;
    try { len = a[1].toInt32(); } catch (e) { return; }
    if (len <= 0 || len > 512) return;
    logEv({ ev: 'ringwrite', len: len, hex: hexOf(a[0], len) });
  },
});

// ---- 发送 flush 真正落 socket ----
function hookSend() {
  try {
    // frida 17 没有 Module.getExportByName，改用模块实例上的 findExportByName
    const p = Process.getModuleByName('ws2_32.dll').findExportByName('send');
    Interceptor.attach(p, {
      onEnter(a) {
        let len = 0; try { len = a[2].toInt32(); } catch (e) {}
        if (len > 0 && len <= 512) logEv({ ev: 'wx.send', len: len, hex: hexOf(a[1], len) });
      },
    });
    logEv({ ev: 'boot', ws2: 'hooked' });
  } catch (e) { logEv({ ev: 'boot', ws2: 'fail:' + e }); }
}
hookSend();

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
    f.write('\n===== probe_state pid=%d %s =====\n' % (pid, time.strftime('%H:%M:%S')))
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

    js = JS.replace('__SETTERS__', json.dumps({str(k): v for k, v in STATE_SETTERS.items()}))
    script = session.create_script(js)
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
