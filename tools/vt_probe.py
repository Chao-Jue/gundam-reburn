#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""在 ivce/协议类的 vtable 槽上做「数据补丁」观测，看客户端真正收到的每条报文。

为什么不用 inline hook：
    实测在 0xAA2D50 / 0xAA2DA4 上挂 frida Interceptor 会被 CPS 发现
    （0x70E9 报 `Addr:AA2D50, C:558BEC83E4, O:E9AF00D302`），客户端随即卡死。
    CPS 校验的是**代码字节**；而处理函数的地址同时存在于**数据段**（vtable）里，
    所以只改 vtable 这 4 字节数据，代码段一个字节都不动。

⚠️ 血的教训（2026-10-23 18:1x）：一次挂满 9 个槽，客户端**立刻闪退**。
    其中 `Codec@vce+0x54` / `iProxyListener@ivce+0x54` 很可能在每帧热路径上，
    每次调用都进一次 JS 回调的开销 + 再入风险，直接把客户端打死。
    ⇒ 默认只挂 1 个槽（`--slots 0`），要挂多个必须显式 `--slots 0,1,...` 且自担风险。

为什么列了 9 个槽：
    `0xBD1610`（分帧解码器）出现在 9 个类的 `+0x20` 槽上，它末尾是
    `mov edx,[esi]; mov edx,[edx+0x54]; call edx` —— 但 `esi` 到底实例化成哪个类，
    静态推不准（`_proto_lounge` 的 +0x54 是 `0xA93EC0`＝只报错 0x242 的空实现，
    `CGVOProtoLounge` 的 +0x54 才是 `0xAA2D50`）。所以全部挂上，谁被调谁计数。

stub（32 位，放在我们自己 Memory.alloc 的内存里，不在模块范围内）：

    60                 pushad
    68 <slotId>        push slotId
    51                 push ecx                 ; this
    FF 74 24 30        push dword [esp+0x30]    ; len   ([E+8])
    FF 74 24 30        push dword [esp+0x30]    ; buf   ([E+4])
    B8 <logfn>         mov  eax, logfn          ; cdecl(buf, len, this, slotId)
    FF D0              call eax
    83 C4 10           add  esp, 0x10
    61                 popad                    ; ecx(this) 原样还回
    68 <orig>          push orig
    C3                 ret                      ; 尾调原函数，栈帧不变

回调里**不调用 send**（native 回调里 send 的可靠性没验证过），只往数组里塞；
Python 每秒 `drain()` 一次，这样"没抓到"和"抓到了但没送出来"能区分开。

用法（客户端要用管理员起，所以本工具也要管理员）：

    python tools/vt_probe.py --dry                     # 只读：打印 9 个候选槽的内容
    python tools/vt_probe.py --seconds 300 --until 0xe13a

输出：`server/vt_probe.log`（一行一条 JSON）。正常退出会还原全部槽。
⚠️ 强杀 python 会让补丁留在进程里（客户端会崩），重启客户端即可恢复。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOG = ROOT / 'server' / 'vt_probe.log'

JS = r"""
'use strict';
(function () {
  const IMG = 0x400000;

  // [槽地址, 名字]；槽地址 = vtable + 0x54
  const CANDIDATES = [
    [0xe14d58, 'CGVOProtoLounge+0x54'],
    [0xe09ac8, '_proto_lounge+0x54'],
    [0xe14948, 'CGVOProtoAuth+0x54'],
    [0xe149e0, 'CGVOProtoBattle+0x54'],
    [0xe03548, '_proto_auth+0x54'],
    [0xe03b10, '_proto_battle+0x54'],
    [0xe63490, 'Codec@vce+0x54'],
    [0xe6a0d0, 'iProxyListener@ivce+0x54'],
    [0xcd07f8, 'CGVOProtoBattleReplaywar+0x54']
  ];
  const CODE_LO = 0x400000, CODE_HI = 0xe0c000;

  let base = null;
  try { base = Process.getModuleByName('GundamOnline_CHINA.exe').base; }
  catch (e) {
    try { base = Process.enumerateModules()[0].base; } catch (e2) { base = null; }
  }
  if (!base) { send({ ev: 'error', why: 'no module base' }); return; }
  const at = (va) => base.add(va - IMG);

  function hexOf(p, n) {
    let s = '';
    for (let i = 0; i < n; i++) {
      try { s += ('0' + p.add(i).readU8().toString(16)).slice(-2); }
      catch (e) { s += '??'; }
    }
    return s;
  }

  // ---- 采集缓冲（回调里只 push，不 send） ----
  const MAXREC = 4000;
  let records = [];
  let counters = {};
  let seq = 0;

  const logfn = new NativeCallback(function (buf, len, self, slotId) {
    const id = (typeof slotId === 'number') ? slotId : Number(slotId.toString());
    counters[id] = (counters[id] || 0) + 1;
    if (records.length >= MAXREC) return;
    const rec = { n: ++seq, slot: id, t: Date.now(), len: len };
    try {
      if (buf.isNull()) { rec.null_buf = true; }
      else {
        rec.op = buf.readU16();
        rec.head = hexOf(buf, Math.min(len > 0 ? len : 16, 24));
      }
    } catch (e) { rec.err = String(e); }
    try {
      // 闸门/配额：仅当 this 是协议对象时有意义。0xE13A 的通道号 = 0xC
      rec.gate = {
        flag: self.add(0x29e + 0x0c).readU8(),
        cnt: self.add(0x4e0 + 0x0c * 0x30).readU32(),
        lim: self.add(0x4e0 + 0x0c * 0x30 + 8).readU32(),
        per: self.add(0x4e0 + 0x0c * 0x30 + 0x10).readU32()
      };
    } catch (e) { rec.gate_err = String(e); }
    records.push(rec);
  }, 'void', ['pointer', 'int', 'pointer', 'int']);

  function u32le(n) { return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]; }

  const slots = [];   // {addr, name, orig, stub, prot}
  for (let i = 0; i < CANDIDATES.length; i++) {
    const [va, name] = CANDIDATES[i];
    const p = at(va);
    let orig = 0, prot = 'r--';
    try {
      orig = p.readU32();
      const r = Process.findRangeByAddress(p);
      if (r && r.protection) prot = r.protection;
    } catch (e) { continue; }
    slots.push({ idx: i, name: name, addr: p, va: va, orig: orig, prot: prot, patched: false, stub: null });
  }

  let patchedAny = false;
  const logAddr = logfn.toUInt32();

  rpc.exports = {
    info() {
      return {
        base: base.toString(),
        logfn: '0x' + logAddr.toString(16),
        slots: slots.map(function (s) {
          const ok = s.orig >= CODE_LO && s.orig < CODE_HI;
          return {
            idx: s.idx, name: s.name, va: '0x' + s.va.toString(16),
            orig: '0x' + s.orig.toString(16), is_code: ok, prot: s.prot,
            patched: s.patched
          };
        })
      };
    },
    patch(onlyIdx) {
      const allow = (onlyIdx === null || onlyIdx === undefined || onlyIdx === '')
        ? null : String(onlyIdx).split(',').map(Number);
      const done = [];
      for (const s of slots) {
        if (allow && allow.indexOf(s.idx) < 0) continue;
        const ok = s.orig >= CODE_LO && s.orig < CODE_HI;
        if (!ok) { done.push([s.name, 'skip(not code)']); continue; }
        const stub = Memory.alloc(64);
        const bytes = [].concat(
          [0x60],
          [0x68], u32le(s.idx),
          [0x51],
          [0xff, 0x74, 0x24, 0x30],
          [0xff, 0x74, 0x24, 0x30],
          [0xb8], u32le(logAddr),
          [0xff, 0xd0],
          [0x83, 0xc4, 0x10],
          [0x61],
          [0x68], u32le(s.orig),
          [0xc3]
        );
        Memory.protect(stub, 64, 'rwx');
        for (let i = 0; i < bytes.length; i++) stub.add(i).writeU8(bytes[i] & 0xff);
        try {
          Memory.protect(s.addr, 4, 'rw-');
          s.addr.writeU32(stub.toUInt32());
          try { Memory.protect(s.addr, 4, s.prot); } catch (e) {}
          s.stub = stub; s.patched = true; patchedAny = true;
          done.push([s.name, '0x' + s.orig.toString(16) + ' -> stub']);
        } catch (e) {
          done.push([s.name, 'FAIL ' + String(e)]);
        }
      }
      return done;
    },
    restore() {
      const done = [];
      for (const s of slots) {
        if (!s.patched) continue;
        try {
          Memory.protect(s.addr, 4, 'rw-');
          s.addr.writeU32(s.orig);
          try { Memory.protect(s.addr, 4, s.prot); } catch (e) {}
          s.patched = false;
          done.push([s.name, 'restored']);
        } catch (e) { done.push([s.name, 'FAIL ' + String(e)]); }
      }
      return done;
    },
    drain() {
      const out = records;
      records = [];
      return { seq: seq, counters: counters, records: out };
    },
    stats() { return { seq: seq, counters: counters, pending: records.length, patched: patchedAny }; }
  };
})();
"""

def find_pid() -> int | None:
    import frida
    try:
        procs = frida.get_local_device().enumerate_processes()
    except Exception:  # noqa: BLE001
        return None
    for p in procs:
        if 'gundam' in p.name.lower():
            return p.pid
    return None


def snapshot_pids() -> set[int]:
    import frida
    try:
        return {p.pid for p in frida.get_local_device().enumerate_processes()
                if 'gundam' in p.name.lower()}
    except Exception:  # noqa: BLE001
        return set()


def run_session(pid: int, args, logf, deadline: float) -> tuple[str, dict]:
    """挂一个进程；返回 (结局, 每槽计数)。结局 = until / lost / expired / fail。"""
    import frida
    try:
        sess = frida.attach(pid)
    except Exception as e:  # noqa: BLE001
        print(f'[!] attach {pid} 失败: {e}')
        return 'fail', {}

    script = sess.create_script(JS)
    script.on('message', lambda m, d: print('[js]', m['payload']) if m.get('type') == 'send' else print('[frida]', m))
    script.load()

    info = script.exports_sync.info()
    print(f"[*] pid={pid} base={info['base']} logfn={info['logfn']}")
    for s in info['slots']:
        print(f"    [{s['idx']}] {s['name']:<30} @{s['va']} 内容={s['orig']:<12}"
              f" {'CODE' if s['is_code'] else 'no-code'}")

    if args.dry:
        logf.close()
        try: sess.detach()
        except Exception: pass
        return 'expired', {}

    # 等槽就绪：壳没解包完时 0xE14D58 里不是 0xAA2D50，绝不能盲改
    want = '0xaa2d50'
    t_slot = time.time() + 90
    while time.time() < t_slot:
        cur = script.exports_sync.info()['slots'][0]['orig']
        if cur == want:
            break
        print(f'[*] 槽还是 {cur}（等壳解包）...')
        time.sleep(3)
    else:
        print('[!] 槽一直不是 0xaa2d50，放弃打补丁')
        logf.close()
        try: sess.detach()
        except Exception: pass
        return 'fail', {}

    done = script.exports_sync.patch(args.slots)
    print('[*] patch:')
    for name, st in done:
        print(f'    {name:<30} {st}')

    counters: dict = {}
    hit = False
    lost = False
    t_end = min(deadline, time.time() + args.seconds)
    print(f'[*] 观测中（到 {time.strftime("%H:%M:%S", time.localtime(t_end))} 或命中 --until 为止）...')
    try:
        while time.time() < t_end:
            time.sleep(1.0)
            try:
                batch = script.exports_sync.drain()
            except Exception as e:  # noqa: BLE001
                print('[!] 会话断了:', e)
                lost = True
                break
            for rec in batch.get('records', []):
                logf.write(json.dumps(rec, ensure_ascii=False) + '\n')
                op = rec.get('op')
                print(f"  #{rec.get('n')} slot={rec.get('slot')} "
                      f"op={('0x%04x' % op) if isinstance(op, int) else '?'} "
                      f"len={rec.get('len')} head={rec.get('head')}")
                if args.until is not None and op == args.until:
                    print(f'[*] 命中 0x{args.until:04x} —— 收工')
                    hit = True
            cs = batch.get('counters') or {}
            counters.update({str(k): v for k, v in cs.items()})
            if hit:
                break
    except KeyboardInterrupt:
        print('\n[*] Ctrl+C')

    try:
        batch = script.exports_sync.drain()
        for rec in batch.get('records', []):
            logf.write(json.dumps(rec, ensure_ascii=False) + '\n')
    except Exception:  # noqa: BLE001
        pass
    try:
        for name, st in script.exports_sync.restore():
            print(f'    restore {name:<30} {st}')
    except Exception as e:  # noqa: BLE001
        print('[!] 还原失败（进程可能已经没了）:', e)
    try: sess.detach()
    except Exception: pass

    print('[*] 每槽调用次数:', counters or '(全 0 —— 这 9 个槽一个都没被调用)')
    return ('until' if hit else 'lost' if lost else 'expired'), counters


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=lambda s: int(s, 0), default=None)
    ap.add_argument('--seconds', type=int, default=900, help='单次观测时长/总时长上限')
    ap.add_argument('--log', default=str(LOG))
    ap.add_argument('--dry', action='store_true', help='只读，打印槽内容')
    ap.add_argument('--until', type=lambda s: int(s, 0), default=None,
                    help='看到这个 opcode 就停（十六进制，如 0xe13a）')
    ap.add_argument('--wait', type=int, default=0, help='最多等这么多秒让客户端出现')
    ap.add_argument('--new-only', action='store_true', help='只认「现在还不存在」的新进程')
    ap.add_argument('--delay', type=int, default=0, help='进程出现后先等这么多秒再 attach')
    ap.add_argument('--slots', default='0',
                    help='要打补丁的槽编号，逗号分隔（默认只挂 0 = CGVOProtoLounge+0x54；'
                         '挂多个有风险，见 docstring）')
    ap.add_argument('--follow', action='store_true',
                    help='跟着客户端走：会话断了/进程换了就重新找新进程再挂，直到抓完或到总时长')
    args = ap.parse_args()

    old_pids = snapshot_pids() if args.new_only else set()
    if args.new_only:
        print(f'[*] 已存在的客户端 pid: {sorted(old_pids) or "无"}（只认之后新出现的）')

    deadline = time.time() + args.seconds + max(args.wait, 0)
    logf = open(args.log, 'a', encoding='utf-8', buffering=1)

    tried: set[int] = set()
    pid = args.pid
    first = True
    while time.time() < deadline:
        if pid is None:
            pid = find_pid()
            while pid is None and time.time() < deadline:
                if first and args.wait:
                    pass
                time.sleep(1)
                pid = find_pid()
            if pid is None:
                print('[!] 等了半天没看到客户端进程')
                break
            if args.new_only and pid in old_pids and not tried:
                print(f'[*] 只看到旧的 pid={pid}，继续等新进程 ...')
                time.sleep(1)
                pid = None
                continue
        if args.delay and pid not in tried:
            print(f'[*] 等 {args.delay}s 让壳解包 ...')
            time.sleep(args.delay)

        tried.add(pid)
        tried.add(pid)
        outcome, _ = run_session(pid, args, logf, deadline)
        first = False
        if outcome in ('until', 'expired'):
            break
        if not args.follow:
            break
        print('[*] 跟随模式：找下一个客户端进程 ...')
        pid = None
        # 排除刚才那个
        while time.time() < deadline:
            time.sleep(2)
            cand = find_pid()
            if cand and cand != pid:
                pid = cand
                break

    logf.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
