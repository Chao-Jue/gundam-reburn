#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""手工完成一次 0xE13A 成功回调 —— 绕开帧层，直接把机师数据喂给客户端。

背景（全部来自本机反汇编，不依赖任何外部资料）：
  `0x43B63A` 是步骤机的 case8：
        call 0x43A680        ; 关等待窗 + 处理两张卡 + 清 0x10615
        cmp byte [game+0x10615], 0
        je  不推进
  而 `0x43A680` 只做"收尾"，真正把数据填进游戏对象的是成功回调
  `FUN_00439190`（= `vt[0x80]` 槽，`0xAF6170` 是它的 thunk，`ret 0x24` = 9 个参数）：

        FUN_00439190(game,
                      P1 result, P2 pilots_eff, P3 pilots_zeon,
                      P4 del_eff, P5 del_zeon, P6 charge,
                      P7 bmg_list, P8 bmg_count, P9 is_tutorial_end)

  P7 会被写成 `*(game+0x10619) = (P7 != 0)`（`0x4392A9` `cmp byte [esp+0x100],0`）。

机师记录内存布局（424B，来自 `FUN_00a956f0` 的 `lea [edi+X]`，线长 398）：
  +0x00 u32 id | +0x04 name[25] | +0x20 u32 last_in | +0x24 u8 troops
  +0x25 u8 level | +0x26 u8 mil_class | +0x28 u16 byword | +0x2C avatar(22)
  +0x44 u32 cmdr_fame | +0x48/4a/4c u16 ×3 | +0x50..0xBC 28×u32
  +0xC0 [116] | +0x134 u32 | +0x138 [31] | +0x157/158/159 u8
  +0x15C/160 u32 | +0x164 [31] | +0x183/184 u8 | +0x188..0x198 5×u32
  +0x19C u8 | +0x1A0 u32

用法（需要管理员，客户端要在跑且停在「正在取得机师数据」）：
    python tools/pilot_call.py --dry      # 只检查环境，不调用
    python tools/pilot_call.py            # 真调用
"""
from __future__ import annotations

import argparse
import sys

JS = r"""
'use strict';
(function () {
  const IMG = 0x400000;
  const GAME_GLOBAL = 0x1161F28;

  let base = null;
  try { base = Process.getModuleByName('GundamOnline_CHINA.exe').base; }
  catch (e) { try { base = Process.enumerateModules()[0].base; } catch (e2) { base = null; } }
  if (!base) { send({ ok: false, why: 'no module base' }); return; }
  const at = (va) => base.add(va - IMG);

  rpc.exports = {
    probe() {
      const g = at(GAME_GLOBAL).readPointer();
      let code = 'ERR';
      try {
        const b = new Uint8Array(at(0x439190).readByteArray(16));
        code = Array.from(b).map(x => ('0' + x.toString(16)).slice(-2)).join('');
      } catch (e) {}
      return {
        base: base.toString(),
        game: g.toString(),
        f10615: g.isNull() ? -1 : g.add(0x10615).readU8(),
        f10619: g.isNull() ? -1 : g.add(0x10619).readU8(),
        f10611: g.isNull() ? -1 : g.add(0x10611).readU8(),
        f1061c: g.isNull() ? -1 : g.add(0x1061c).readU32(),
        f10620: g.isNull() ? -1 : g.add(0x10620).readU32(),
        code439190: code
      };
    },

    hideWait(id, value) {
      const g = at(GAME_GLOBAL).readPointer();
      if (g.isNull()) return { ok: false, why: 'game == NULL' };
      // 0x43B5AD 的 case：0x439FB0(game, 11, 0.0f) + 0x42EFB0(game)
      const f1 = new NativeFunction(at(0x439fb0), 'void',
                                    ['pointer', 'int32', 'float'], 'thiscall');
      const f2 = new NativeFunction(at(0x42efb0), 'void',
                                    ['pointer'], 'thiscall');
      let e1 = null, e2 = null;
      try { f1(g, id, value); } catch (e) { e1 = String(e); }
      try { f2(g); } catch (e) { e2 = String(e); }
      return { ok: e1 === null && e2 === null, e1: e1, e2: e2,
               id: id, value: value,
               f10615: g.add(0x10615).readU8() };
    },

    closeWait() {
      const g = at(GAME_GLOBAL).readPointer();
      if (g.isNull()) return { ok: false, why: 'game == NULL' };
      const before = {
        f10615: g.add(0x10615).readU8(),
        f10611: g.add(0x10611).readU8()
      };
      // 0x43A680 = 步骤机 case8 的"离开等待界面"：处理两张卡 + 0x439FB0(5,1.0f) + 清 0x10615
      const fn = new NativeFunction(at(0x43a680), 'void', ['pointer'], 'thiscall');
      let err = null;
      try { fn(g); } catch (e) { err = String(e); }
      let after = null;
      try {
        after = { f10615: g.add(0x10615).readU8(), f10611: g.add(0x10611).readU8() };
      } catch (e) {}
      return { ok: err === null, err: err, before: before, after: after };
    },

    callUp() {
      const g = at(GAME_GLOBAL).readPointer();
      if (g.isNull()) return { ok: false, why: 'game == NULL' };

      const REC = 0x1a8;                 // 424
      const eff = Memory.alloc(REC);
      const zeon = Memory.alloc(REC);

      // 秩序侧：一个可显示的机师
      eff.writeU32(5);                   // +0x00 pilot_id
      eff.add(4).writeUtf8String('TEST');// +0x04 name[25]
      eff.add(0x24).writeU8(0);          // troops: 线上 0 基 => 0 = 秩序
      eff.add(0x25).writeU8(1);          // level
      eff.add(0x26).writeU8(0);          // mil_class
      eff.add(0x157).writeU8(0);         // channel_id
      eff.add(0x158).writeU8(1);         // state_bits
      eff.add(0x198).writeU32(1);        // level_point

      // 抵抗侧：留空（全 0）

      const before = {
        f10615: g.add(0x10615).readU8(),
        f10619: g.add(0x10619).readU8()
      };

      const P = ['pointer', 'pointer', 'pointer', 'pointer', 'pointer',
                 'pointer', 'pointer', 'pointer', 'pointer', 'pointer'];
      const fn = new NativeFunction(at(0x439190), 'void', P, 'thiscall');

      let err = null;
      try {
        const z = ptr(0);
        fn(g, z, eff, zeon, z, z, z, z, z, z);
      } catch (e) {
        err = String(e);
      }

      let after = null;
      try {
        after = {
          f10615: g.add(0x10615).readU8(),
          f10619: g.add(0x10619).readU8(),
          f10611: g.add(0x10611).readU8()
        };
      } catch (e) {}

      return {
        ok: err === null,
        err: err,
        eff: eff.toString(),
        zeon: zeon.toString(),
        before: before,
        after: after
      };
    }
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=lambda s: int(s, 0), default=None)
    ap.add_argument('--dry', action='store_true', help='只读环境，不调用')
    ap.add_argument('--hide-id', type=lambda x: int(x, 0), default=5,
                    help='hide 模式第一个参数（阶段/窗口 ID）；进入等待时用的是 5')
    ap.add_argument('--hide-val', type=float, default=0.0,
                    help='hide 模式第二个参数（float）')
    ap.add_argument('--mode', choices=['hide', 'close', 'up'], default='hide',
                    help='close=调 0x43A680 关等待窗（安全）；up=调 FUN_00439190 灌数据（易崩）')
    args = ap.parse_args()

    import frida
    pid = args.pid or find_pid()
    if not pid:
        print('[!] 找不到 GundamOnline_CHINA.exe（客户端没在跑？）')
        return 2
    print(f'[*] pid = {pid}')

    try:
        sess = frida.attach(pid)
    except Exception as e:  # noqa: BLE001
        print(f'[!] attach 失败: {e}（需要管理员）')
        return 3

    script = sess.create_script(JS)
    msgs: list[str] = []
    script.on('message', lambda m, d: msgs.append(str(m)))
    script.load()

    info = script.exports_sync.probe()
    print('[*] base      =', info['base'])
    print('[*] game      =', info['game'])
    print('[*] +0x10615  =', info['f10615'])
    print('[*] +0x10619  =', info['f10619'])
    print('[*] +0x10611  =', info['f10611'])
    print('[*] +0x1061c  =', hex(info['f1061c']), '(UI/进度管理器指针)')
    print('[*] +0x10620  =', hex(info['f10620']))
    print('[*] 0x439190 首字节 =', info['code439190'])

    if args.dry:
        print('[*] --dry：不调用。')
        return 0

    if args.mode == 'hide':
        print('[*] 调用 0x439FB0(game,%s,%s) + 0x42EFB0(game) —— 试点隐藏等待窗 ...'
              % (args.hide_id, args.hide_val))
        r = script.exports_sync.hide_wait(args.hide_id, args.hide_val)
    elif args.mode == 'close':
        print('[*] 调用 0x43A680(game) —— 关闭等待窗 / 离开等待界面 ...')
        r = script.exports_sync.close_wait()
    else:
        print('[*] 调用 FUN_00439190(game, 0, eff, zeon, 0,0,0, 0,0, 0) ...')
        r = script.exports_sync.call_up()
    print('[*] 返回:', r)
    if r.get('err'):
        print('[!] 调用时抛错:', r['err'])
    return 0 if r.get('ok') else 1


if __name__ == '__main__':
    raise SystemExit(main())
