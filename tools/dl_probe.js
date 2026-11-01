// hook 下载回复处理链，只记录、不修改，判断是"没进函数"还是"中途异常"
// 目标（基址 0x400000，已解包）：
//   0x544790  FUN_00544790  recv 处理：按名字查节点 → 解包 → switch → erase
//   0x9AE510  std::map::erase
//   0xA46480  解包（判决点候选）
//   0x9BEC20  case 67 的 Load
//
// 判读：
//   enter 544790 出现、但没有 erase  → 中途抛异常（查 0xA46480 / Load 的 leave 有没有）
//   enter 544790 完全不出现          → 上层没派发进来
//   erase 出现                       → 其实成功了，卡点在别处

const ADDR = {
  recv:   0x544790,
  erase:  0x9AE510,
  unpack: 0xA46480,
  load67: 0x9BEC20,
};

const names = {};
for (const k in ADDR) names[ADDR[k]] = k;

function hook(addr, tag) {
  try {
    Interceptor.attach(ptr(addr), {
      onEnter(args) {
        this.t0 = Date.now();
        // thiscall：ecx = this，args[] 为栈参数
        const ctx = this.context;
        send({
          t: 'enter',
          tag: tag,
          thisp: ctx.ecx.toString(),
          a0: args[0].toString(),
          a1: args[1].toString(),
          a2: (() => { try { return args[2].toInt32(); } catch (e) { return null; } })(),
        });
      },
      onLeave(retval) {
        send({
          t: 'leave',
          tag: tag,
          ret: (() => { try { return retval.toInt32(); } catch (e) { return null; } })(),
          ms: Date.now() - this.t0,
        });
      },
    });
    send({ t: 'armed', tag: tag, addr: '0x' + addr.toString(16) });
  } catch (e) {
    send({ t: 'error', tag: tag, err: String(e) });
  }
}

for (const k in ADDR) hook(ADDR[k], k);
send({ t: 'ready' });
