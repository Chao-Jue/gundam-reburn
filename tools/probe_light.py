"""轻量探针：只挂已被验证安全的点，状态靠"轮询内存"而不是"给代码下断点"。

为什么重写：上一版给 9 个 `mov [esi+0x280], imm` 指令位置下钩子，结果客户端
**每次进入 state 2 就崩（0xc0000005，10/10 复现）**。而 13:40 那轮只挂 RingWrite
时连登 7 次都没事。所以嫌疑锁定在"中段指令级 hook"上。

本版做法：
  1. 只在 RingWrite(0xc034f0) 下钩子 —— 已验证安全 —— 顺手记下 Socket 对象地址
  2. 用 setInterval 每 100ms **只读内存** [Socket+0x280]，变化就记录（零代码修改）
  3. 挂 ws2_32 的 send / recv，看真正上线的字节（这是 13:40 那轮验证过安全的）

用法：python tools/probe_light.py --seconds 1800      （单个 pid）
      python tools/auto_probe.py --light 1            （自动跟随重启）
日志：server/probe_light.log
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
LOG = os.path.join(ROOT, 'server', 'probe_light.log')
MOD = 'GundamOnline_CHINA.exe'

JS = r'''
'use strict';
const BASE = 0x400000;
const mod = Process.getModuleByName('GundamOnline_CHINA.exe');
function at(off) { return mod.base.add(off - BASE); }
function logEv(o) { try { send(o); } catch (e) {} }
function hexOf(p, n) {
  try { if (!p || p.isNull() || n <= 0) return null;
    const b = new Uint8Array(p.readByteArray(Math.min(n, 512)));
    return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  } catch (e) { return 'ERR'; }
}

let SOCK = null;
let lastState = -1;

// ---- 调用栈采样（只采前 N 次，避免拖慢/带崩） ----
// 目的：拿到"解密 → 应用层队列 → 分发"这条链上的真实 VA，下一轮好定点 hook。
// Thread.backtrace 给的是绝对地址，减模块基址得"相对 0x400000 的偏移"。
let BT_LEFT = 40;
function btOf(ctx) {
  if (BT_LEFT <= 0) return null;
  BT_LEFT--;
  try {
    const fr = Thread.backtrace(ctx, Backtracer.FUZZY);
    const out = [];
    for (let i = 0; i < fr.length && i < 12; i++) {
      try { out.push(fr[i].sub(mod.base).toInt32() >>> 0); } catch (e) { out.push(null); }
    }
    return out;
  } catch (e) { return 'ERR'; }
}

// ---- RingWrite：唯一安全的代码钩子，用来拿到 Socket 地址 + 待发字节 ----
Interceptor.attach(at(0xc034f0), {
  onEnter(a) {
    let len = 0;
    try { len = a[1].toInt32(); } catch (e) { return; }
    let self = null;
    try { self = this.context.ecx; } catch (e) {}
    try {
      const s = this.context.ecx.sub(0x1f8);
      if (s && !s.isNull()) SOCK = s;
    } catch (e) {}
    if (len > 0 && len <= 512) {
      logEv({ ev: 'ring', len: len, hex: hexOf(a[0], len),
              self: self ? self.toString() : null, bt: btOf(this.context) });
    }
  },
});

// ---- 状态轮询（纯内存读，不碰代码） ----
setInterval(function () {
  if (!SOCK) return;
  let st = -1, bits = -1;
  try { st = SOCK.add(0x280).readU32(); } catch (e) { SOCK = null; return; }
  try { bits = SOCK.add(0x270).readU32(); } catch (e) {}
  if (st !== lastState) {
    lastState = st;
    logEv({ ev: 'STATE', st: st, bits: bits, sock: SOCK.toString() });
  }
}, 100);

// ---- 断连错误码：0xbf89a0(this, flag, code) ----
Interceptor.attach(at(0xbf89a0), {
  onEnter(a) {
    let code = null, flag = null;
    try { flag = a[0].toInt32(); } catch (e) {}
    try { code = a[1].toInt32(); } catch (e) {}
    logEv({ ev: 'ERROR', code: code, flag: flag });
  },
});

// ---- 启动时把指定 RVA 的**运行时字节**抄出来 ----
// 壳里 .text 的文件内容是密文，静态反汇编没用；活内存里才是真代码。
// 用 --dump-rva 传入（逗号分隔 RVA），日志里出 {ev:'code', off, hex}。
const DUMP_RVA = __DUMP_RVA__;
const DUMP_LEN = __DUMP_LEN__;
for (let i = 0; i < DUMP_RVA.length; i++) {
  const off = DUMP_RVA[i];
  logEv({ ev: 'code', off: off, hex: hexOf(at(off), DUMP_LEN) });
}

// ---- ⚠️ 不要在这里 hook 0x7d5009 ----
// 0x7d5009 是收包分发器（参数 [esp+0xdc] 就是 32 位消息 ID），但它在登录界面是
// **高频函数**：frida 的 Interceptor 会改写它的首字节，Themida 的完整性校验立刻发现，
// 客户端当场退出（2026-10-17 实测多次）。
// 本探针只在**低频/安全**的位置下钩子（cB / cA / RingWrite / ws2），
// 需要看 0x7d5009 的参数请改用硬件断点（调试寄存器不改字节），见 tools/start_msgid.cmd 的说明。
// 今天改用"静态挖调用者"的方式：dump 0x7d4000~0x7d6000，离线找 `call 0x7d5009`，
// 反汇编调用者看它把哪个内存偏移塞进参数。

// ---- 会话加解密：0xc00a70 / 0xc00bd0(bits, in, sess, out) ----
let keyDumped = 0;
let ctxDumped = 0;
function logCrypt(tag, off) {
  Interceptor.attach(at(off), {
    onEnter(a) {
      this.p = [a[0], a[1], a[2], a[3]];
      let v = [];
      for (let i = 0; i < 4; i++) { try { v.push(this.p[i].toInt32() >>> 0); } catch (e) { v.push(null); } }
      logEv({ ev: tag + '.in', args: v, m1: hexOf(a[1], 16), m2: hexOf(a[2], 16),
              m3: hexOf(a[3], 16), bt: btOf(this.context) });
      // 只 dump 第一次：把密钥调度区整块抄下来，离线复现加解密用
      if (keyDumped < 1) {
        keyDumped++;
        logEv({ ev: 'KEYDUMP', bits: v[0], ptr: v[2], hex: hexOf(a[2], 0x100) });
      }
      // 上下文前后各抄一份，用来定位"多块之间到底哪个字节在变"
      if (ctxDumped < 6) {
        logEv({ ev: tag + '.ctx_pre', i: ctxDumped, hex: hexOf(a[2], 0x60) });
      }
    },
    onLeave(r) {
      logEv({ ev: tag + '.out', ret: (r ? r.toInt32() : null),
              m1: hexOf(this.p[1], 16), m2: hexOf(this.p[2], 16), m3: hexOf(this.p[3], 16) });
      if (ctxDumped < 6) {
        logEv({ ev: tag + '.ctx_post', i: ctxDumped, hex: hexOf(this.p[2], 0x60) });
        ctxDumped++;
      }
    },
  });
}
logCrypt('cA', 0xc00a70);
logCrypt('cB', 0xc00bd0);

// ---- ws2 收发真身 ----
function hookWs2() {
  try {
    const m = Process.getModuleByName('ws2_32.dll');
    Interceptor.attach(m.findExportByName('send'), {
      onEnter(a) {
        let len = 0; try { len = a[2].toInt32(); } catch (e) {}
        if (len > 0 && len <= 512) logEv({ ev: 'SEND', len: len, hex: hexOf(a[1], len) });
      },
    });
    Interceptor.attach(m.findExportByName('recv'), {
      onEnter(a) { this.buf = a[1]; this.want = a[2].toInt32(); },
      onLeave(r) {
        let n = 0; try { n = r.toInt32(); } catch (e) {}
        if (n > 0) logEv({ ev: 'RECV', n: n, hex: hexOf(this.buf, n) });
      },
    });
    logEv({ ev: 'boot', ws2: 'hooked' });
  } catch (e) { logEv({ ev: 'boot', ws2: 'fail:' + e }); }
}
hookWs2();
logEv({ ev: 'ready' });
'''


def find_pid():
    """找客户端 pid。

    踩过的坑（都别再走）：
      1. `tasklist /FI "IMAGENAME eq GundamOnline_CHINA.exe"` 在这个环境**经常返回空**，
         于是拿到垃圾 pid 去 attach → `ProcessNotRespondingError`;
      2. 用 PowerShell 的 `Get-Process *Gundam*` 有时也会返回过期 pid / 被 sandbox 拦，
         本机实测同样不可靠。
    **目前唯一稳定的是：`tasklist` 全量列表 + 关键字匹配**（和 server 侧脚本一致）。
    """
    try:
        out = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'], capture_output=True)
        txt = out.stdout.decode('mbcs', 'replace')
        for line in txt.splitlines():
            if MOD.lower() in line.lower():
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2 and parts[1].isdigit():
                    return int(parts[1])
    except Exception:
        pass
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=int)
    ap.add_argument('--seconds', type=int, default=1800)
    ap.add_argument('--follow', action='store_true', help='客户端崩了自动跟新 pid')
    ap.add_argument('--dump-rva', default='', help='启动时抄这些 RVA 的活内存字节，逗号分隔')
    ap.add_argument('--dump-len', type=int, default=96)
    a = ap.parse_args()

    dump_rva = [int(x.strip(), 0) for x in a.dump_rva.split(',') if x.strip()]
    js_src = JS.replace('__DUMP_RVA__', json.dumps(dump_rva)) \
               .replace('__DUMP_LEN__', str(a.dump_len))

    f = open(LOG, 'a', encoding='utf-8')

    def on_msg(msg, data):
        if msg.get('type') == 'error':
            line = '[JS-ERR] ' + str(msg.get('description'))
        else:
            p = msg.get('payload')
            line = json.dumps(p, ensure_ascii=False) if isinstance(p, dict) else str(p)
        f.write(time.strftime('%H:%M:%S ') + line + '\n')
        f.flush()

    cur, sess = None, None
    t0 = time.time()
    try:
        while time.time() - t0 < a.seconds:
            pid = a.pid if not a.follow else find_pid()
            if pid != cur:
                if sess:
                    try: sess.detach()
                    except Exception: pass
                    sess = None
                cur = pid
                if pid:
                    f.write('\n===== probe_light pid=%d %s =====\n' % (pid, time.strftime('%H:%M:%S')))
                    f.flush()
                    try:
                        sess = frida.attach(pid)
                        sc = sess.create_script(js_src)
                        sc.on('message', on_msg)
                        sc.load()
                        print('[+] attached pid=%d' % pid, flush=True)
                    except Exception as e:
                        # pid 可能刚退出（find_pid 拿到的是瞬时结果），或注入被拒。
                        # 这里**绝不能**让异常冒出去把整个探针杀掉。
                        print('[-] attach %d failed: %r' % (pid, e), flush=True)
                        try:
                            sess.detach()
                        except Exception:
                            pass
                        sess = None
                        cur = None
                        time.sleep(1)
                else:
                    print('[-] waiting for client', flush=True)
            elif not a.follow and not cur:
                break
            time.sleep(2)
            if a.follow is False:
                # 单 pid 模式：进程没了就退出
                try:
                    if pid and not os.path.exists('/proc/%d' % pid):
                        pass
                except Exception:
                    pass
    except KeyboardInterrupt:
        pass
    finally:
        if sess:
            try: sess.detach()
            except Exception: pass
        f.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
