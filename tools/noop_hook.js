/* 对照组脚本：注入 frida，但一个 hook 都不装。
 *
 * 用途：区分 Themida 的「Sorry, this application cannot run under a Virtual
 * Machine」到底是被什么触发的：
 *
 *   A. 这个空脚本 -> 仍然弹  => frida 的「存在」本身（模块 / 线程 / 注入痕迹）
 *                               就足以让 Themida 判定为虚拟机。
 *   B. 空脚本不弹、完整脚本弹 => 是我们 hook 的某个 API 造成的
 *                               （典型是时序检测：被 Interceptor 加了一层跳板后，
 *                                壳测出来的耗时不对）。
 *
 * 用法：
 *   python tools/run_hooked.py --no-elevate --idle-script --seconds 10
 */
'use strict';
const CFG = (typeof __CFG_JSON__ === 'object') ? __CFG_JSON__ : {};

send({ ev: 'ready', note: 'noop: 不装任何 hook', arch: Process.arch,
       ptrSize: Process.pointerSize, pid: Process.id, fake: CFG.fake || null });

// 只报告一下 agent 模块自己占在哪，方便对比
try {
  const m = Process.findModuleByName('frida-agent.dll');
  send({ ev: 'agent', base: m ? m.base.toString() : null, size: m ? m.size : null });
} catch (e) {}
