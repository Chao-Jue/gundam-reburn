// ⛔⛔ 已于 2026-10-24 停用，不要再加载 ⛔⛔
// 它会把 0xE13A 分支里 0xACFE76（读 result 的 call a5a310）等指令改成 jmp，
// 客户端反外挂 CPS 会在 0x70E9 自检里明确报出这条篡改：
//     Addr:ACFE76, C:E895A4F8FF, O:E9892F0503
// 而 0xACFE76 正是机师列表解析的第一步 —— 挂着它做机师实验 = 在被劫持的代码路径上做实验。
// start_local.cmd 已移除 --pilot-hook。

// pilot_hook.js —— 0xE13A 解析链定点观测（精简版）
//
// ⛔ 2026-10-23 实测教训：**绝不能 hook 0xAA2D50 / 0xAA2DA4**。
//    客户端发来的 0x70E9（CPS 反外挂自检报告）正文里出现了
//      "Addr:AA2D50, C:558BEC83E4, O:E9AF00D302"
//    —— CPS 在读那两处的原始字节做校验，被 frida 的 inline hook 改写后
//    客户端直接卡死在「频道登录中」。撤掉这两个点后必须重启客户端。
//
// 原则：
//   · 只挂 0xE13A 分支内部的冷指令（一条消息只走一次）
//   · 只读内存，不写内存、不改参数和返回值
//   · 不在函数入口 / 分发器 / 任何 CPS 可能校验的公共热路径上挂
//
// 保留的 5 个定点（VA 为未重定位镜像地址，基址 0x400000）：
//   0xACFE76  0xE13A 读 result 前   -> end-cur = 客户端认定的正文长度
//   0xACFE82  任一字段读失败出口
//   0xAD007D  cmp cur, end          -> 差几字节
//   0xAD009C  长度校验通过后的成功分支（真正的 oracle）
//   0xAD0085  长度不符专用出口

'use strict';

(function () {
  const IMG_BASE = 0x400000;

  const A_BODY      = 0xacfe76;
  const A_FIELDFAIL = 0xacfe82;
  const A_TAILCMP   = 0xad007d;
  const A_OK        = 0xad009c;
  const A_BADLEN    = 0xad0085;

  let base = null;
  try { base = Process.getModuleByName('GundamOnline_CHINA.exe').base; }
  catch (e) { try { base = Process.enumerateModules()[0].base; } catch (e2) { base = null; } }
  if (!base) { send({ tag: 'pilot', msg: 'no module base' }); return; }
  const at = (va) => base.add(va - IMG_BASE);

  send({ tag: 'pilot', msg: 'base=' + base + ' (CPS-safe: only 5 inner points)' });

  let nBody = 0, nOk = 0, nBad = 0, nFail = 0;

  function hook(va, name, fn) {
    try {
      Interceptor.attach(at(va), {
        onEnter(args) {
          try { fn(args, this); }
          catch (e) { send({ tag: 'pilot', msg: name + ' err ' + e }); }
        }
      });
      send({ tag: 'pilot', msg: 'attached ' + name + ' @0x' + va.toString(16) });
    } catch (e) {
      send({ tag: 'pilot', msg: 'attach ' + name + ' FAIL ' + e });
    }
  }

  // 0xACFE76: cursor struct at esp+0x1C(cur) / esp+0x20(end)
  hook(A_BODY, 'body', (args, ctx) => {
    const sp = ptr(ctx.context.esp);
    const cur = sp.add(0x1c).readPointer();
    const end = sp.add(0x20).readPointer();
    nBody++;
    send({
      tag: 'pilot',
      msg: '[e13a] #' + nBody + ' clientBody=' + end.sub(cur).toInt32() +
           '  (cur=' + cur + ' end=' + end + ')'
    });
  });

  // 0xAD007D: cmp cur,[esp+0x18]
  hook(A_TAILCMP, 'tailcmp', (args, ctx) => {
    const sp = ptr(ctx.context.esp);
    const cur = sp.add(0x14).readPointer();
    const end = sp.add(0x18).readPointer();
    let eq = false;
    try { eq = cur.equals(end); } catch (e) { eq = (cur.toInt32() === end.toInt32()); }
    send({
      tag: 'pilot',
      msg: '[tail] cur-end=' + cur.sub(end).toInt32() +
           ' equal=' + eq + '  (remain=' + end.sub(cur).toInt32() + ')'
    });
  });

  hook(A_OK, 'ok', () => {
    nOk++;
    send({ tag: 'pilot', msg: '*** 0xE13A accepted (cur==end) #' + nOk });
  });
  hook(A_BADLEN, 'badlen', () => {
    nBad++;
    send({ tag: 'pilot', msg: '!!! 0xE13A length mismatch #' + nBad });
  });
  hook(A_FIELDFAIL, 'fieldfail', () => {
    nFail++;
    send({ tag: 'pilot', msg: '!!! 0xE13A field read fail #' + nFail });
  });

  rpc.exports = {
    summary() {
      return { body: nBody, ok: nOk, badlen: nBad, fieldfail: nFail };
    }
  };
})();
