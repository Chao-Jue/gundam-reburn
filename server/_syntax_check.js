/*
 * xgg_hook.js —— 在 Win32 API 边界上"骗过"保护模块的驱动加载检查。
 *
 * 目标（见 server/分析与绕过方案.md §5 路线 B）：
 *   保护模块 (XGGLib / DLIB-DLOADER / K_DS) 通过 SCM 安装并启动内核驱动
 *   CPS.sys。StartService 失败后它弹窗并 ExitProcess(-1)。我们不改被
 *   VMProtect 保护的模块代码，只在 advapi32!StartServiceW（以及它的
 *   上下游）上，让它"看到"驱动加载成功。
 *
 * 本脚本由 tools/run_hooked.py 注入，CFG 在注入前替换。
 * 默认策略：只记录 + 只伪造 StartServiceW 的返回值，先看日志往哪走。
 *
 * Frida 17 API 备注：Module.getExportByName / findExportByName 已移除，
 * 改用 模块实例.getExportByName()。
 */
'use strict';

const CFG = {"connectTo":"127.0.0.1:30000","connectToPort":30000,"connectToBytes":[127,0,0,1]};

// 伪造给客户的"驱动设备句柄"。取一个不像真句柄的值，方便在别的 API 里识别。
const FAKE_HANDLE = 0x43505330;   // 'CPS0'

/* ------------------------------------------------------------------ */
/* 基础工具                                                            */
/* ------------------------------------------------------------------ */
function now() { return Date.now(); }
function logEv(o) { try { o.t = now(); send(o); } catch (e) {} }
function logErr(tag, e) {
  logEv({ ev: 'err', tag: tag, err: String(e), stack: e && e.stack ? String(e.stack) : null });
}
function rdWStr(p) { try { return p && !p.isNull() ? p.readUtf16String() : null; } catch (e) { return null; } }
function rdAStr(p) { try { return p && !p.isNull() ? p.readAnsiString() : null; } catch (e) { return null; } }
function hx(n) { return '0x' + (n >>> 0).toString(16); }

// 句柄 -> 路径。用来把 DeviceIoControl 的真实设备认出来（例如那次 code=0x390008）。
const HANDLE_MAP = {};
function mapHandle(h, p) { try { if (p) HANDLE_MAP[h >>> 0] = p; } catch (e) {} }
function lookupHandle(h) { try { const v = HANDLE_MAP[h >>> 0]; return v === undefined ? null : v; } catch (e) { return null; } }

/* ------------------------------------------------------------------ */
/* 重入保护（重要！）                                                   */
/* ------------------------------------------------------------------ */
/* frida-agent.dll 自己也会调用 VirtualAlloc / VirtualProtect / LoadLibraryA/W /
 * GetProcAddress / CreateFileW / CreateThread 这些我们 hook 的 API。如果在回调里
 * 再去 Process.findModuleByAddress / Thread.backtrace，就会重入 agent 内部结构，
 * 实测直接 0xc0000005 崩掉整个进程，且崩点是 frida-agent.dll+0xc0919c
 * （Windows 事件日志 Application Error 里记录得非常清楚）。
 *
 * 表现是"游戏跑十秒左右自己退出"，非常容易被误判成游戏/保护模块的问题，
 * 所以这里必须挡住：来自 agent 模块的调用，以及回调里再触发的嵌套调用，一律放行。
 */
const AGENT_MODS = [];
(function () {
  for (const n of ['frida-agent.dll', 'frida-agent-32.dll', 'frida-agent-64.dll',
                   'frida-agent-modulated.dll']) {
    try { const m = Process.findModuleByName(n); if (m) AGENT_MODS.push(m); } catch (e) {}
  }
  try {
    for (const m of Process.enumerateModules()) {
      if (/frida/i.test(m.name) && AGENT_MODS.indexOf(m) < 0) AGENT_MODS.push(m);
    }
  } catch (e) {}
})();

function inAgent(p) {
  try {
    if (!p) return false;
    for (let i = 0; i < AGENT_MODS.length; i++) {
      const m = AGENT_MODS[i];
      if (p.compare(m.base) >= 0 && p.compare(m.base.add(m.size)) < 0) return true;
    }
  } catch (e) {}
  return false;
}

// 回调里再发生嵌套调用时 >0（frida 的 JS 回调是串行的，全局计数够用）
let __depth = 0;

// 二分定位用：想关掉哪些 hook。dll 名不分大小写，名字用 "dll!Export" 形式。
const SKIP_DLL = {};
const SKIP_NAME = {};
const ONLY_NAME = {};
let ONLY_COUNT = 0;
(function () {
  const dl = (CFG && CFG.skipDlls) || [];
  for (let i = 0; i < dl.length; i++) SKIP_DLL[String(dl[i]).toLowerCase()] = 1;
  const nm = (CFG && CFG.skipNames) || [];
  for (let i = 0; i < nm.length; i++) SKIP_NAME[String(nm[i]).toLowerCase()] = 1;
  const on = (CFG && CFG.onlyNames) || [];
  for (let i = 0; i < on.length; i++) { ONLY_NAME[String(on[i]).toLowerCase()] = 1; ONLY_COUNT++; }
})();

// 白名单模式下，不在名单里的 hook 一律不装。
// 这是**默认**行为，原因见下面的 Themida 说明。
function onlyAllows(dll, name) {
  if (!ONLY_COUNT) return true;
  return !!ONLY_NAME[dll.toLowerCase() + '!' + name.toLowerCase()];
}

/* ------------------------------------------------------------------ */
/* 为什么要"最小必要集"                                                  */
/* ------------------------------------------------------------------ */
/* Themida 在启动 stub 里会校验一批系统 API 的**入口字节**，一旦发现被打了
 * 内联跳板（也就是 frida 的 Interceptor）就判定为"虚拟机/被调试"，弹
 *   "Sorry, this application cannot run under a Virtual Machine"
 * 然后自杀。实测（每组 3 次）：
 *
 *   空脚本（不装任何 hook）                      触发 0/3
 *   完整脚本（45 个 hook）                       触发 5/6
 *   跳过 ntdll!KiUserExceptionDispatcher         触发 0/3   <= 在检查名单里
 *   跳过 user32!MessageBoxTimeoutA/W             触发 0/3   <= 在检查名单里
 *   跳过 ntdll!LdrLoadDll                        触发 2/3
 *   跳过 kernel32 / advapi32 全部                触发 2/3、1/3（没影响）
 *
 * 关键是：这个检测**不调用**任何 API（检测瞬间日志里一条 API 事件都没有），
 * 纯属对内存里代码的扫描。所以只能靠"少挂 hook"来规避。
 *
 * 结论：默认只装伪造驱动链所必需的那十几个 hook；需要排查别的问题时再用
 * --full 把全部 hook 打开（代价是可能触发 Themida）。                     */

// 把地址解析成 "模块+0x偏移"，认调用者最直观
function sym(a) {
  try {
    const m = Process.findModuleByAddress(a);
    return m ? (m.name + '+0x' + a.sub(m.base).toString(16)) : a.toString();
  } catch (e) { return a ? a.toString() : '?'; }
}
function btOf(ctx, depth) {
  const out = [];
  try {
    let frames = Thread.backtrace(ctx, Backtracer.FUZZY).slice(0, depth || 10);
    for (const a of frames) out.push(sym(a));
  } catch (e) { out.push('bt-err:' + String(e)); }
  return out;
}
function hexOf(p, n) {
  try {
    if (!p || p.isNull() || !n || n <= 0) return null;
    const b = new Uint8Array(p.readByteArray(Math.min(n, 128)));
    return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  } catch (e) { return null; }
}
function rangeInfo(a) {
  try {
    const r = Process.findRangeByAddress(a);
    return r ? { base: r.base.toString(), size: r.size, prot: r.protection } : null;
  } catch (e) { return null; }
}

// sockaddr_in -> "ip:port"（只处理 AF_INET/AF_INET6 的常见情况）
function sockaddrStr(p) {
  try {
    if (!p || p.isNull()) return null;
    const fam = p.readU16();
    if (fam === 2) {
      const port = (p.add(2).readU8() << 8) | p.add(3).readU8();
      const ip = [p.add(4).readU8(), p.add(5).readU8(), p.add(6).readU8(), p.add(7).readU8()].join('.');
      return ip + ':' + port;
    }
    if (fam === 23) {
      let parts = [];
      for (let i = 8; i < 24; i += 2) parts.push(p.add(i).readU16().toString(16));
      const port = (p.add(2).readU8() << 8) | p.add(3).readU8();
      return '[' + parts.join(':') + ']:' + port;
    }
    return 'family=' + fam;
  } catch (e) { return null; }
}

// UNICODE_STRING* -> 字符串
function readUnicodeString(p) {
  try {
    const len = p.readU16();
    const buf = p.add(4).readPointer();
    return buf.readUtf16String(len / 2);
  } catch (e) { return null; }
}

function findExport(modName, expName) {
  try { return Process.getModuleByName(modName).getExportByName(expName); }
  catch (e) { logEv({ ev: 'noexport', mod: modName, name: expName }); return null; }
}

let _CopyFileW = null, _SetLastError = null, _GetCurrentThreadId = null;
try {
  const k32 = Process.getModuleByName('kernel32.dll');
  _CopyFileW = new NativeFunction(k32.getExportByName('CopyFileW'), 'int',
                                  ['pointer', 'pointer', 'int'], { abi: 'stdcall' });
} catch (e) {}
try {
  _SetLastError = new NativeFunction(Process.getModuleByName('kernel32.dll')
                                     .getExportByName('SetLastError'), 'void', ['uint32'],
                                     { abi: 'stdcall' });
} catch (e) {}
try {
  _GetCurrentThreadId = new NativeFunction(Process.getModuleByName('kernel32.dll')
                                           .getExportByName('GetCurrentThreadId'), 'uint32', [],
                                           { abi: 'stdcall' });
} catch (e) {}

let FAKE_SHELL_HANDLE = null;
const _gmnSeen = {};
function isShellPath(p) { return !!p && /acopcshell/i.test(p); }

// 统一的库加载处理：ACOPCShell.dll 缺失时让它"加载成功"，并记录它要哪些导出
function handleLibLoad(name, pathArg, retval, ctx) {
  if (pathArg && pathArg.toLowerCase().indexOf('ws2_32') >= 0) hookWs2();
  if (isShellPath(pathArg)) {
    const wasNull = retval.isNull();
    logEv({ ev: name, path: pathArg, realRet: retval.toString(), isNull: wasNull ? 1 : 0,
            bt: btOf(ctx, 12) });
    if (CFG.fake.shell && wasNull) {
      FAKE_SHELL_HANDLE = Process.getModuleByName('ntdll.dll').base;
      retval.replace(FAKE_SHELL_HANDLE);
      logEv({ ev: 'fake', api: name, path: pathArg, handle: FAKE_SHELL_HANDLE.toString() });
    }
    return;
  }
  if (pathArg && pathArg.toLowerCase().indexOf('system32') < 0 && retval) {
    logEv({ ev: name, path: pathArg, ret: retval.toString() });
  }
}

/* ------------------------------------------------------------------ */
/* 抓驱动文件：StartService 前它一定已经躺在磁盘上了                     */
/* ------------------------------------------------------------------ */
const _seen = {};

function saveData(srcPath, data, tag) {
  try {
    if (!data || !data.byteLength) return false;
    if (_seen[srcPath] === data.byteLength) return false;   // 同文件同尺寸，跳过
    _seen[srcPath] = data.byteLength;
    const base = srcPath.replace(/^.*[\\/]/, '');
    const dst = CFG.dumpDir + '\\' + base + '.cap_' + tag + '_' + now() + '.bin';
    let ok = false;
    if (_CopyFileW) {
      try { ok = _CopyFileW(Memory.allocUtf16String(srcPath), Memory.allocUtf16String(dst), 0) !== 0; } catch (e) {}
    }
    if (!ok) {
      try {
        const w = new File(dst, 'wb');
        w.writeBytes(data);
        w.close();
        ok = true;
      } catch (e) { logEv({ ev: 'dump_write_err', dst: dst, err: String(e) }); }
    }
    logEv({ ev: 'dump', src: srcPath, dst: dst, bytes: data.byteLength, ok: ok ? 1 : 0, tag: tag });
    return ok;
  } catch (e) { logErr('saveData', e); return false; }
}

function tryRead(path, tag) {
  try {
    const f = new File(path, 'rb');
    const data = f.readBytes();
    f.close();
    return saveData(path, data, tag);
  } catch (e) { return false; }
}

function sweep(tag) {
  for (const p of CFG.candidates) tryRead(p, tag);
}

/* ------------------------------------------------------------------ */
/* 统一 hook 封装                                                      */
/* ------------------------------------------------------------------ */
function hook(dll, name, spec) {
  // 二分定位用：CFG.skipDlls / CFG.skipNames 可以把一部分 hook 关掉。
  // 目的：Themida 的「cannot run under a Virtual Machine」只在装了 hook 时才触发
  //（空脚本 1/1 通过，完整脚本 5/6 触发），需要找出是哪一个。
  if (SKIP_DLL[dll.toLowerCase()]) { logEv({ ev: 'skip', dll: dll, name: name }); return; }
  if (SKIP_NAME[(dll.toLowerCase() + '!' + name.toLowerCase())]) {
    logEv({ ev: 'skip', dll: dll, name: name }); return;
  }
  if (!onlyAllows(dll, name)) { logEv({ ev: 'skip', dll: dll, name: name }); return; }
  const addr = findExport(dll, name);
  if (!addr) return;
  try {
    Interceptor.attach(addr, {
      onEnter(args) {
        this.__skip = false;
        if (__depth > 0 || inAgent(this.returnAddress)) { this.__skip = true; return; }
        try {
          if (spec.enter) { __depth++; try { spec.enter.call(this, args); } finally { __depth--; } }
        } catch (e) { logErr('enter:' + name, e); }
      },
      onLeave(retval) {
        // 已进入过一次的嵌套调用：直接放行，避免把返回值改坏、也避免重入崩溃
        if (this.__skip) return;
        if (__depth > 0 || inAgent(this.returnAddress)) return;
        try {
          if (spec.leave) { __depth++; try { spec.leave.call(this, retval); } finally { __depth--; } }
        } catch (e) { logErr('leave:' + name, e); }
      },
    });
    logEv({ ev: 'hooked', dll: dll, name: name });
  } catch (e) { logErr('attach:' + name, e); }
}

/* ------------------------------------------------------------------ */
/* SCM 一族：CreateService -> StartService -> Query/Control -> Delete    */
/* ------------------------------------------------------------------ */

// 13 个参数：hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess,
//            dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, ...
hook('advapi32.dll', 'CreateServiceW', {
  enter(a) {
    const bin = rdWStr(a[7]);
    logEv({ ev: 'CreateServiceW', service: rdWStr(a[1]), display: rdWStr(a[2]),
            binary: bin, type: a[4].toInt32(), startType: a[5].toInt32(),
            errorControl: a[6].toInt32() });
    if (bin) tryRead(bin, 'createservice');
  },
  leave(r) {
    logEv({ ev: 'CreateServiceW.ret', ret: r.toString(), isNull: r.isNull() ? 1 : 0 });
    if (CFG.fake.createService && r.isNull()) {
      r.replace(ptr(CFG.fakeHandle));
      logEv({ ev: 'fake', api: 'CreateServiceW', handle: CFG.fakeHandle });
    }
  },
});

hook('advapi32.dll', 'OpenSCManagerW', {
  enter(a) { logEv({ ev: 'OpenSCManagerW', machine: rdWStr(a[0]), db: rdWStr(a[1]), access: hx(a[2].toInt32()) }); },
  leave(r) { logEv({ ev: 'OpenSCManagerW.ret', ret: r.toString(), isNull: r.isNull() ? 1 : 0 }); },
});

hook('advapi32.dll', 'OpenServiceW', {
  enter(a) { logEv({ ev: 'OpenServiceW', name: rdWStr(a[1]), access: hx(a[2].toInt32()) }); },
  leave(r) {
    logEv({ ev: 'OpenServiceW.ret', ret: r.toString(), isNull: r.isNull() ? 1 : 0 });
    if (CFG.fake.openService && r.isNull()) { r.replace(ptr(CFG.fakeHandle)); logEv({ ev: 'fake', api: 'OpenServiceW' }); }
  },
});

hook('advapi32.dll', 'StartServiceW', {
  enter(a) {
    logEv({ ev: 'StartServiceW', handle: a[0].toString(), argc: a[1].toInt32() });
    sweep('startservice');           // 此刻驱动文件还在磁盘上 —— 抢在 StartService 之前抓走
  },
  leave(r) {
    const orig = r.toInt32();
    logEv({ ev: 'StartServiceW.ret', ret: orig, orig: orig });
    if (CFG.fake.startService) {
      r.replace(ptr(1));             // 骗它：服务已启动
      try { if (_SetLastError) _SetLastError(0); } catch (e) {}
      logEv({ ev: 'fake', api: 'StartServiceW', forced: 1 });
    }
  },
});

// SERVICE_STATUS_PROCESS（InfoLevel = SC_STATUS_PROCESS_INFO = 0）36 字节
function fillStatus(buf, size) {
  if (!buf || buf.isNull() || size < 28) return;
  buf.writeU32(CFG.serviceType || 1);        // dwServiceType
  buf.add(4).writeU32(4);                    // dwCurrentState = SERVICE_RUNNING
  buf.add(8).writeU32(1);                    // dwControlsAccepted = SERVICE_ACCEPT_STOP
  for (let o = 12; o < 28; o += 4) buf.add(o).writeU32(0);
  if (size >= 32) buf.add(28).writeU32(0x1234);   // dwProcessId（假）
  if (size >= 36) buf.add(32).writeU32(0);        // dwServiceFlags
}

hook('advapi32.dll', 'QueryServiceStatusEx', {
  enter(a) {
    this.buf = a[2]; this.cb = a[3].toInt32(); this.pcb = a[4];
    logEv({ ev: 'QueryServiceStatusEx', handle: a[0].toString(), level: a[1].toInt32(), cb: this.cb });
  },
  leave(r) {
    logEv({ ev: 'QueryServiceStatusEx.ret', ret: r.toInt32() });
    if (CFG.fake.queryStatus) {
      fillStatus(this.buf, this.cb);
      if (this.pcb && !this.pcb.isNull()) this.pcb.writeU32(this.cb >= 36 ? 36 : 28);
      r.replace(ptr(1));
      logEv({ ev: 'fake', api: 'QueryServiceStatusEx', state: 4 });
    }
  },
});

hook('advapi32.dll', 'QueryServiceStatus', {
  enter(a) { this.buf = a[1]; logEv({ ev: 'QueryServiceStatus', handle: a[0].toString() }); },
  leave(r) {
    if (CFG.fake.queryStatus) {
      fillStatus(this.buf, 28);
      r.replace(ptr(1));
      logEv({ ev: 'fake', api: 'QueryServiceStatus', state: 4 });
    }
  },
});

hook('advapi32.dll', 'ControlService', {
  enter(a) { this.buf = a[2]; logEv({ ev: 'ControlService', handle: a[0].toString(), control: a[1].toInt32() }); },
  leave(r) {
    logEv({ ev: 'ControlService.ret', ret: r.toInt32() });
    if (CFG.fake.controlService) { fillStatus(this.buf, 28); r.replace(ptr(1)); logEv({ ev: 'fake', api: 'ControlService' }); }
  },
});

hook('advapi32.dll', 'DeleteService', {
  enter(a) { logEv({ ev: 'DeleteService', handle: a[0].toString() }); },
  leave(r) {
    logEv({ ev: 'DeleteService.ret', ret: r.toInt32() });
    if (CFG.fake.deleteService) { r.replace(ptr(1)); logEv({ ev: 'fake', api: 'DeleteService' }); }
  },
});

hook('advapi32.dll', 'CloseServiceHandle', {
  enter(a) { logEv({ ev: 'CloseServiceHandle', handle: a[0].toString() }); },
  leave() {},
});

/* ------------------------------------------------------------------ */
/* 驱动握手：CreateFile("\\.\CPS") + DeviceIoControl                    */
/* ------------------------------------------------------------------ */
hook('kernel32.dll', 'CreateFileW', {
  enter(a) {
    const p = rdWStr(a[0]);
    this.path = p;
    // isCps：只伪造这一种；isDevice：所有 \\.\ / \\?\ 形式都给记录（找壳的探测行为）
    this.isCps = !!(p && CFG.devicePatterns.some(x => p.toLowerCase().indexOf(x) >= 0));
    this.isDevice = !!(p && (this.isCps || /^\\\\[.?]\\/.test(p)));
    this.interesting = !!(p && (this.isDevice || CFG.sysHints.some(h => p.toLowerCase().indexOf(h) >= 0)));
    if (this.isDevice) {
      logEv({ ev: 'CreateFileW(device)', path: p, access: hx(a[1].toInt32()), share: a[2].toInt32(), disp: a[4].toInt32() });
    } else if (this.interesting) {
      logEv({ ev: 'CreateFileW', path: p, access: hx(a[1].toInt32()), share: a[2].toInt32(), disp: a[4].toInt32() });
    }
  },
  leave(r) {
    if (!r.isNull() && r.toInt32() !== -1) mapHandle(r.toInt32(), this.path);
    if (this.isDevice) {
      logEv({ ev: 'CreateFileW(device).ret', path: this.path, ret: r.toString(), invalid: (r.toInt32() === -1) ? 1 : 0 });
      if (CFG.fake.openDevice && this.isCps) {
        r.replace(ptr(FAKE_HANDLE));                  // 骗它：设备对象存在
        try { if (_SetLastError) _SetLastError(0); } catch (e) {}
        logEv({ ev: 'fake', api: 'CreateFileW', device: this.path, handle: FAKE_HANDLE });
      }
    } else if (this.interesting) {
      logEv({ ev: 'CreateFileW.ret', path: this.path, ret: r.toString(), isNull: r.isNull() ? 1 : 0, invalid: (r.toInt32() === -1) ? 1 : 0 });
    }
  },
});

// 伪造 IOCTL 的输出缓冲。
//
// 之前只对 0x222059 写"版本号"，但实测模块**从来不调** 0x222059 —— 它调的是
//   0x222015 / 0x22202d / 0x222035   (in 0,  out 0)
//   0x22204e / 0x222045              (in 20, out 0)
//   0x222055                          (in 20, out 8)  <= 疑似"查询驱动/保护版本"
//   0x22207c                          (in 16, out 0)
// 0x222055 的 8 字节输出一直没被填过，模块读到的是未初始化数据，然后在
// 匿名代码区 0x28d9f 处 `mov dword ptr [ecx+0x18], ebx` 用坏指针写 -> 0xC0000005。
//
// 入参结构 = 「内核驱动的内存读写原语」：
//   0x222055: in 20 字节 = { u32 size; u32 op; u32 x; u32 len; u32 addr }
// 实测样本: 14000000 03000000 00000000 08000000 44fc1a00
//           size=20    op=3      x=0       len=8      addr=0x1afc44
// op=3 = 「读 addr 起的 len 字节」。另一笔 op=3,len=6,addr=0x73db005 在调用时
// 该处的内存是 `8b10 8bc8 8b4238 ffe0`
//   （mov edx,[eax] / mov ecx,eax / mov eax,[edx+0x38] / jmp eax）
// —— 是模块**自己代码的字节**。所以这不是"查版本号"，而是完整性自校验。
//
// 驱动侧印证（tools/disasm_driver.py）：CPS.sys 导入
//   IoAllocateMdl / MmBuildMdlForNonPagedPool / MmMapLockedPagesSpecifyCache /
//   MmUnmapLockedPages / MmIsAddressValid / KeAttachProcess / KeDetachProcess /
//   ProbeForRead / IoGetCurrentProcess
// 正是"把调用者指定的用户态地址做成 MDL → 映射 → 拷出来"的标准写法。
//
// 输出的两种候选语义（两种都实现，默认 ptr）：
//   @read:ptr     读到一块缓冲，out 里回**缓冲地址**（模块拿它再解引用）
//   @read:inline  读到的字节**直接写进 out**（模块把 out 当数据本身）
//   @alloc:<n>    回一个 n 字节全零缓冲的地址（旧行为，仅用于对照）
// 之前只回零缓冲属于"糊过去"：模块拿到的校验字节全是 0，和它自己的代码不一致。
const IOCTL_OUT = (CFG && CFG.ioctlOut) || {};

function decodeIoIn(buf, size) {
  try {
    if (!buf || buf.isNull() || size < 20) return null;
    const a = buf.add(0x10).readU32() >>> 0;
    return { size: buf.readU32(), op: buf.add(4).readU32(), x: buf.add(8).readU32(),
             len: buf.add(0xc).readU32(), addr: hx(a), addrInt: a,
             at: hexOf(ptr(a), 16) };
  } catch (e) { return null; }
}

// 安全读：逐段检查可读性，读不到的部分留零。
// 绝不拿一个可能非法的地址直接 readByteArray —— 那条路径上目标进程会真的吃
// 一个 0xC0000005，把我们要观察的场景污染掉。
function safeRead(addrInt, len) {
  const out = new Uint8Array(len);
  let off = 0, bad = 0;
  while (off < len) {
    const p = ptr(addrInt + off);
    let r = null;
    try { r = Process.findRangeByAddress(p); } catch (e) {}
    if (!r || String(r.protection || '').charAt(0) !== 'r') {
      bad += len - off;                     // 不可读：整段补零并记账
      break;
    }
    const avail = Math.min(len - off, r.base.add(r.size).sub(p).toInt32());
    try { out.set(new Uint8Array(p.readByteArray(avail)), off); }
    catch (e) { bad += avail; }
    off += avail;
  }
  return { bytes: out, bad: bad };
}

function u8hex(u8, n) {
  const m = Math.min(n === undefined ? u8.length : n, u8.length);
  const a = [];
  for (let i = 0; i < m; i++) a.push(u8[i].toString(16).padStart(2, '0'));
  return a.join('');
}

function hexToBytes(s) {
  const h = String(s).replace(/[^0-9a-fA-F]/g, '');
  const out = [];
  for (let i = 0; i + 1 < h.length; i += 2) out.push(parseInt(h.substr(i, 2), 16));
  return out;
}

function u32le(v) { return [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]; }

// 给某些 IOCTL 用的"每次都返回同一个假对象"的缓冲，避免每次分配
const _ioScratch = {};

function fillIoctlOut(code, inBuf, inSize, out, outSize) {
  if (!out || out.isNull() || outSize <= 0) return { moved: 0, note: null };
  const key = hx(code);
  let spec = IOCTL_OUT[key];
  if (spec === undefined && code === 0x222055) spec = '@read:ptr';
  let bytes = null, note = null;

  if (spec && /^@read/i.test(spec)) {
    // 「真读」：按入参 addr/len 把目标进程的内存读出来
    const d = decodeIoIn(inBuf, inSize);
    if (!d) {
      note = 'read:no-input';
    } else if (!d.addrInt || !d.len || d.len > 0x40000) {
      note = 'read:bad-args op=' + d.op + ' len=' + d.len + ' addr=' + d.addr;
    } else {
      const r = safeRead(d.addrInt, d.len);
      note = 'read op=' + d.op + ' addr=' + d.addr + ' len=' + d.len +
             ' bad=' + r.bad + ' data=' + u8hex(r.bytes);
      if (/inline/i.test(spec)) {
        bytes = Array.from(r.bytes.slice(0, Math.max(outSize, 4)));
      } else {
        const n = Math.max(16, (d.len + 15) & ~15);
        const k = key + ':read:' + n;
        if (!_ioScratch[k]) _ioScratch[k] = Memory.alloc(n);
        _ioScratch[k].writeByteArray(r.bytes);       // 缓冲里放**真实内容**
        bytes = u32le(_ioScratch[k].toInt32() >>> 0);
      }
    }
  } else if (spec && /^@alloc/i.test(spec)) {
    // 分配 n 字节全零缓冲，把它的**地址**作为输出写回去
    const n = parseInt(String(spec).split(':')[1] || '4096', 10) || 4096;
    const k = key + ':' + n;
    if (!_ioScratch[k]) _ioScratch[k] = Memory.alloc(n);
    bytes = u32le(_ioScratch[k].toInt32() >>> 0);
  } else if (spec) {
    bytes = hexToBytes(spec);
  }

  if ((!bytes || !bytes.length) && outSize >= 4) {
    // 其余 outSize>=4 的：通用成功回复 = 版本号（小端）+ 补零
    bytes = u32le(CFG.deviceVersion >>> 0);
    while (bytes.length < Math.min(outSize, 64)) bytes.push(0);
  }
  if (!bytes || !bytes.length) return { moved: 0, note: note };
  const n = Math.min(outSize, bytes.length);
  out.writeByteArray(bytes.slice(0, n));
  return { moved: n, note: note };
}

hook('kernel32.dll', 'DeviceIoControl', {
  enter(a) {
    this.h = a[0].toInt32();
    this.code = a[1].toInt32() >>> 0;
    this.inBuf = a[2];
    this.inSize = a[3].toInt32();
    this.out = a[4];
    this.outSize = a[5].toInt32();
    this.br = a[6];
    const ours = (this.h === FAKE_HANDLE) ? 1 : 0;
    logEv({ ev: 'DeviceIoControl', h: a[0].toString(), code: hx(this.code),
            inSize: this.inSize, outSize: this.outSize, ours: ours,
            in: ours ? hexOf(this.inBuf, this.inSize) : null,
            inDec: ours ? decodeIoIn(this.inBuf, this.inSize) : null,
            dev: lookupHandle(this.h),
            bt: btOf(this.context, ours ? 8 : 8) });
  },
  leave(r) {
    const ret = r.toInt32();
    logEv({ ev: 'DeviceIoControl.ret', ret: ret, code: hx(this.code),
            out: (this.h === FAKE_HANDLE) ? hexOf(this.out, this.outSize) : null });
    if (CFG.fake.deviceIo && this.h === FAKE_HANDLE) {
      const res = fillIoctlOut(this.code, this.inBuf, this.inSize, this.out, this.outSize);
      if (this.br && !this.br.isNull()) this.br.writeU32(res.moved);
      r.replace(ptr(1));
      try { if (_SetLastError) _SetLastError(0); } catch (e) {}
      logEv({ ev: 'fake', api: 'DeviceIoControl', code: hx(this.code), moved: res.moved,
              note: res.note,
              out: hexOf(this.out, Math.min(this.outSize, 16)) });
    }
  },
});

// 模块可能会对设备句柄做这些事；只针对我们的假句柄放行，其余原样
function handleApi(name, nargs) {
  hook('kernel32.dll', name, {
    enter(a) { this.ours = (a[0].toInt32() === FAKE_HANDLE); if (this.ours) logEv({ ev: name, h: a[0].toString() }); },
    leave(r) {
      if (this.ours && CFG.fake.deviceIo) {
        if (name === 'GetFileSize' || name === 'GetFileSizeEx') { r.replace(ptr(1)); }
        else { r.replace(ptr(1)); }
        try { if (_SetLastError) _SetLastError(0); } catch (e) {}
      }
    },
  });
}
['ReadFile', 'WriteFile', 'SetFilePointer', 'SetFilePointerEx', 'GetFileSize', 'GetFileSizeEx',
 'FlushFileBuffers', 'SetEndOfFile'].forEach(n => handleApi(n, 0));

hook('kernel32.dll', 'CloseHandle', {
  enter(a) { this.ours = (a[0].toInt32() === FAKE_HANDLE); },
  leave(r) { if (this.ours) { r.replace(ptr(1)); logEv({ ev: 'CloseHandle', fakeHandle: 1 }); } },
});

/* ------------------------------------------------------------------ */
/* 万一它绕过 SCM 直接 NtLoadDriver                                     */
/* ------------------------------------------------------------------ */
hook('ntdll.dll', 'NtLoadDriver', {
  enter(a) { logEv({ ev: 'NtLoadDriver', regpath: rdWStr(a[0]) }); },
  leave(r) { logEv({ ev: 'NtLoadDriver.ret', ret: r.toInt32(), status: hx(r.toInt32()) }); },
});
hook('ntdll.dll', 'ZwLoadDriver', {
  enter(a) { logEv({ ev: 'ZwLoadDriver', regpath: rdWStr(a[0]) }); },
  leave(r) { logEv({ ev: 'ZwLoadDriver.ret', ret: r.toInt32(), status: hx(r.toInt32()) }); },
});

/* ------------------------------------------------------------------ */
/* 线程图谱：区分"主线程"和"工作线程"，退出到底是谁干的                 */
/* ------------------------------------------------------------------ */
const MAIN_TID = (function () { try { return _GetCurrentThreadId ? _GetCurrentThreadId() : null; } catch (e) { return null; } })();
const THREADS = {};
logEv({ ev: 'main_tid', tid: MAIN_TID });

const _regionDumped = {};

// 把"不在任何模块里"的线程入口所在的内存区整块 dump 下来。
// 用处：崩溃地址实测总是 该区基址 + 0x28d9f（三次运行都一致），把这块内存拿到
// 手就能直接反汇编看它到底在干什么。
function dumpRange(a, tag) {
  try {
    const r = Process.findRangeByAddress(a);
    if (!r || !r.size) return null;
    const key = r.base.toString() + ':' + r.size;
    if (_regionDumped[key]) return null;
    _regionDumped[key] = 1;
    const dst = CFG.dumpDir + '\\region_' + r.base.toString().replace('0x', '') +
                '_' + r.size + '_' + (tag || 'x') + '.bin';
    const CHUNK = 4096;
    let w = null, ok = 0, err = null, bad = [];
    try {
      w = new File(dst, 'wb');
      for (let off = 0; off < r.size; off += CHUNK) {
        const n = Math.min(CHUNK, r.size - off);
        let buf = null;
        try {
          buf = r.base.add(off).readByteArray(n);
        } catch (e) {
          bad.push('0x' + off.toString(16));
          buf = new ArrayBuffer(n);           // 不可读的页留空占位，保持偏移对齐
        }
        if (!buf) { bad.push('0x' + off.toString(16)); buf = new ArrayBuffer(n); }
        w.write(buf);
      }
      ok = 1;
    } catch (e) {
      err = String(e);
    } finally {
      try { if (w) w.close(); } catch (e) {}
    }
    logEv({ ev: 'dump', src: 'region ' + r.base.toString(), dst: dst,
            bytes: r.size, tag: tag || 'region', ok: ok,
            prot: r.protection, file: r.file ? r.file.path : null,
            badChunks: bad.length, badHead: bad.slice(0, 8), err: err });
    return dst;
  } catch (e) {
    logEv({ ev: 'dump_err', err: String(e), tag: tag || null });
    return null;
  }
}

hook('kernel32.dll', 'CreateThread', {
  enter(a) { this.start = a[2]; this.param = a[3]; this.tidOut = a[5]; },
  leave(r) {
    let tid = null;
    try { if (this.tidOut && !this.tidOut.isNull()) tid = this.tidOut.readU32(); } catch (e) {}
    if (tid) THREADS[tid] = 'worker';
    let m = null;
    try { if (this.start && !this.start.isNull()) m = Process.findModuleByAddress(this.start); } catch (e) {}
    const unknown = !!(this.start && !this.start.isNull() && !m);
    if (unknown) dumpRange(this.start, 'threadstart');
    logEv({ ev: 'CreateThread', handle: r.toString(), tid: tid,
            start: this.start ? sym(this.start) : null,
            rng: unknown ? rangeInfo(this.start) : null,
            bytes: unknown ? hexOf(this.start, 32) : null,
            callers: btOf(this.context, 6) });
  },
});
hook('ntdll.dll', 'RtlCreateUserThread', {
  enter(a) { this.start = a[1]; },
  leave(r) { logEv({ ev: 'RtlCreateUserThread', status: hx(r.toInt32()), start: this.start ? sym(this.start) : null }); },
});

/* ------------------------------------------------------------------ */
/* 退出去向：它到底是谁让它退的、退出码多少、弹了什么                   */
/* ------------------------------------------------------------------ */
function tidNow() { try { return _GetCurrentThreadId ? _GetCurrentThreadId() : null; } catch (e) { return null; } }
function whoAmI() { const t = tidNow(); return (t === MAIN_TID) ? 'main' : 'worker'; }

hook('kernel32.dll', 'ExitProcess', {
  enter(a) { logEv({ ev: 'ExitProcess', code: a[0].toInt32(), codeHex: hx(a[0].toInt32()),
                     tid: tidNow(), who: whoAmI(), bt: btOf(this.context, 12) }); },
});
hook('kernel32.dll', 'TerminateProcess', {
  enter(a) { logEv({ ev: 'TerminateProcess', h: a[0].toString(), code: a[1].toInt32(),
                     tid: tidNow(), who: whoAmI(), bt: btOf(this.context, 10) }); },
});
hook('kernel32.dll', 'ExitThread', {
  enter(a) { logEv({ ev: 'ExitThread', code: a[0].toInt32(), tid: tidNow(), who: whoAmI() }); },
});
hook('kernel32.dll', 'TerminateThread', {
  enter(a) { logEv({ ev: 'TerminateThread', h: a[0].toString(), code: a[1].toInt32() }); },
});
hook('ntdll.dll', 'RtlExitUserProcess', {
  enter(a) { logEv({ ev: 'RtlExitUserProcess', code: a[0].toInt32(), tid: tidNow(), bt: btOf(this.context, 12) }); },
});
hook('ntdll.dll', 'NtTerminateProcess', {
  enter(a) { logEv({ ev: 'NtTerminateProcess', h: a[0].toString(), code: a[1].toInt32(),
                     tid: tidNow(), who: whoAmI(), bt: btOf(this.context, 12) }); },
});
hook('ntdll.dll', 'NtTerminateThread', {
  enter(a) { logEv({ ev: 'NtTerminateThread', h: a[0].toString(), code: a[1].toInt32(), tid: tidNow() }); },
});
hook('ntdll.dll', 'RtlExitUserThread', {
  enter(a) {
    logEv({ ev: 'RtlExitUserThread', code: a[0].toInt32(), tid: tidNow(), who: whoAmI(),
            bt: btOf(this.context, 12) });
  },
});
hook('ntdll.dll', 'RaiseException', {
  enter(a) { logEv({ ev: 'RaiseException', code: hx(a[0].toInt32()) }); },
});
hook('user32.dll', 'MessageBoxW', {
  enter(a) { logEv({ ev: 'MessageBoxW', text: rdWStr(a[1]), caption: rdWStr(a[2]), type: a[3].toInt32() }); },
});
hook('user32.dll', 'MessageBoxA', {
  enter(a) { logEv({ ev: 'MessageBoxA', text: rdAStr(a[1]), caption: rdAStr(a[2]), type: a[3].toInt32() }); },
});
hook('user32.dll', 'CreateDialogIndirectParamW', {
  enter(a) { logEv({ ev: 'CreateDialogIndirectParamW', hInst: a[0].toString(), templ: a[1].toString() }); },
});

/* ------------------------------------------------------------------ */
/* 异常：抓访问违例（0xC0000005）的现场                                  */
/* ------------------------------------------------------------------ */
const _excSeen = {};
hook('ntdll.dll', 'KiUserExceptionDispatcher', {
  enter(a) {
    let code = null, rec = null;
    try {
      const er = a[0];
      code = hx(er.readU32());
      rec = {
        code: code,
        flags: er.add(4).readU32(),
        addr: sym(er.add(0x0c).readPointer()),
        addrRaw: er.add(0x0c).readPointer().toString(),
        nparams: er.add(0x10).readU32(),
        info0: er.add(0x14).readPointer().toString(),
        info1: er.add(0x18).readPointer().toString(),
      };
    } catch (e) { rec = { err: String(e) }; }
    const n = (_excSeen[code] = (_excSeen[code] || 0) + 1);
    // 壳内部会用异常做控制流，同一个码会刷成千上万次：每个码只详录前 3 次
    if (n <= 3) {
      logEv({ ev: 'EXCEPTION', n: n, rec: rec, tid: tidNow(), who: whoAmI(), bt: btOf(this.context, 14) });
    }
  },
});
// 分辨率探测：它到底"看到"多少像素、从哪问来的
const _smSeen = {};
hook('user32.dll', 'GetSystemMetrics', {
  enter(a) { this.i = a[0].toInt32(); },
  leave(r) {
    const want = [0, 1, 78, 79, 80, 116, 117];
    if (want.indexOf(this.i) < 0) return;
    const key = this.i + ':' + r.toInt32();
    if (_smSeen[key]) return;
    _smSeen[key] = 1;
    logEv({ ev: 'GetSystemMetrics', idx: this.i, val: r.toInt32(), caller: sym(this.returnAddress) });
  },
});
/* ------------------------------------------------------------------ */
/* 分辨率检查探针                                                       */
/* ------------------------------------------------------------------ */
/* 检查点在 RVA 0x58f166..0x58f18d（未命名主节，明文 x86）：
 *
 *   mov eax, [0x1162058]        ; eax = 配置对象
 *   mov esi, [eax]              ; esi = 要求宽度
 *   mov edi, [eax+4]            ; edi = 要求高度
 *   mov ebx, [0xcaa448]         ; GetSystemMetrics
 *   call ebx                    ; GetSystemMetrics(0) -> 屏幕宽
 *   push 1
 *   mov [esp+0x3c], eax         ; 存屏幕宽
 *   call ebx                    ; GetSystemMetrics(1) -> 屏幕高（stdcall 被调用方清栈）
 *   cmp [esp+0x38], esi ; jb 0x58f7da   ; 屏幕宽 < 要求宽 -> 弹框
 *   cmp eax, edi        ; jb 0x58f7da   ; 屏幕高 < 要求高 -> 弹框
 *
 *   call 的返回地址: 第一次 0x58f179、第二次 0x58f181（frida 记的就是它）。
 *   注意 GetSystemMetrics 是 stdcall —— 返回后 esp 比 push 后高 4 字节，
 *   所以 0x58f181 那条 `cmp [esp+0x38]` 读的就是刚存进去的屏幕宽，没算错。
 *
 * 为了不碰被 Themida 覆盖的主节（怕撞自校验），这里不 hook 游戏代码，
 * 只在 GetSystemMetrics 的 onEnter 里读调用点现场：esi/edi 就是阈值，
 * eax（第一次调用时）还是配置对象指针。
 */
const RES_SLOT_RVA = 0x1162058;
const _resSeen = {};

function p2n(p) { try { return p ? Number(p) & 0xffffffff : null; } catch (e) { return null; } }
function safeU32(p) { try { return p.readU32(); } catch (e) { return null; } }
function safePtr(p) { try { return p.readPointer(); } catch (e) { return null; } }

hook('user32.dll', 'GetSystemMetrics', {
  enter(a) {
    try {
      if (!GAME_MOD) return;
      const off = ((this.returnAddress.sub(GAME_MOD.base).toInt32()) >>> 0);
      if (off !== 0x58f179 && off !== 0x58f181) return;
      if (_resSeen[off]) return;
      _resSeen[off] = 1;
      const ctx = this.context;
      const rec = {
        ev: '分辨率检查', at: hx(off), idx: a[0].toInt32(),
        esi: p2n(ctx.esi), edi: p2n(ctx.edi), eax: p2n(ctx.eax),
        ebp: p2n(ctx.ebp), esp: p2n(ctx.esp),
      };
      // 第二次调用时（返回 0x58f181），栈上 P+0x3c 就是刚存下的屏幕宽
      rec.stackW = safeU32(ctx.esp.add(0x40));
      if (off === 0x58f179) {
        const obj = ctx.eax;
        rec.obj = obj.toString();
        rec.objFields = [safeU32(obj), safeU32(obj.add(4)),
                         safeU32(obj.add(8)), safeU32(obj.add(0xc)),
                         safeU32(obj.add(0x10)), safeU32(obj.add(0x14))];
        const gp = GAME_MOD.base.add(RES_SLOT_RVA);
        const op = safePtr(gp);
        rec.slotAddr = gp.toString();
        rec.slotPtr = op ? op.toString() : null;
        rec.slotMatchesObj = (op && op.equals(obj)) ? 1 : 0;
        if (op) rec.slotFields = [safeU32(op), safeU32(op.add(4))];
      }
      logEv(rec);
    } catch (e) { logErr('resProbe', e); }
  },
});

hook('gdi32.dll', 'GetDeviceCaps', {
  enter(a) { this.i = a[1].toInt32(); },
  leave(r) {
    // 8=HORZRES 10=VERTRES 118=DESKTOPHORZRES 117=DESKTOPVERTRES
    if ([8, 10, 117, 118].indexOf(this.i) >= 0) {
      logEv({ ev: 'GetDeviceCaps', idx: this.i, val: r.toInt32(), caller: sym(this.returnAddress) });
    }
  },
});

// 弹窗家族补全：run10/run11 那两个对话框都没走 MessageBoxW
['MessageBoxTimeoutW', 'MessageBoxTimeoutA', 'MessageBoxIndirectA', 'MessageBoxExW',
 'CreateDialogParamW', 'CreateDialogParamA', 'DialogBoxIndirectParamW',
 'DialogBoxIndirectParamA', 'DialogBoxParamA'].forEach(function (n) {
  hook('user32.dll', n, {
    enter(a) {
      logEv({ ev: n, tid: tidNow(), caller: sym(this.returnAddress), bt: btOf(this.context, 12) });
    },
  });
});

/* ------------------------------------------------------------------ */
/* 崩溃现场（VEH）                                                      */
/* ------------------------------------------------------------------ */
/* 实测进程会以 0xC0000005 挂在"不在任何模块里"的匿名 r-x 区：
 *     区域基址 + 0x28d71  或  +0x28d9f
 * 系统事件日志里"出错模块名称: unknown / 错误偏移: 0x07468d9f"就是这个。
 * 光看反汇编推不出坏指针从哪来，所以在 VEH（最靠前）把现场记下来：
 *   寄存器 + 崩溃点前后指令字节（事后用 capstone 算有效地址）+ 栈前 128 字节。
 *
 * 返回 false = 不拦截，异常照常往上传递，不改变原有行为。
 * 注意：VEH 走 RtlAddVectoredExceptionHandler，**不修改任何 API 的入口字节**，
 * 所以不会踩到 Themida 的"入口字节扫描"（那条才是反虚拟机弹窗的触发条件）。
 */
if (CFG.veh) {
  try {
    function nreg(v) {
      try {
        if (v === undefined || v === null) return null;
        return (typeof v === 'number') ? hx(v) : v.toString();
      } catch (e) { return null; }
    }
    let excCount = 0;
    let avCount = 0;
    const ok = Process.setExceptionHandler(function (d) {
      try {
        const c = d.context;
        const isAv = String(d.type || '').indexOf('access-violation') >= 0;
        if (isAv || excCount < 20) {
          excCount++;
          const mem = {};
          if (isAv && avCount < 3) {
            // 关键：把各寄存器指向的内存也 dump 出来。
            // 实测崩溃点是个环形队列出队操作（region+0x27d70）：
            //   push ecx
            //   eax = [ecx+0x90]                 ; head
            //   edx = (head+1) % [ecx+0x98]      ; [ecx+0x98] = 容量
            //   if ([ecx+0x94] == head) return 0 ; 空
            //   esi = [ecx + head*8]             ; <== 崩在这里
            // 结构推测 = { u64 buf[N]; u32 head@0x90; u32 tail@0x94; u32 cap@0x98 }，
            // 所以 dump 长度必须 > 0xA0 才看得到 head/tail/cap。
            avCount++;
            const regsList = { eax: c.eax, ebx: c.ebx, ecx: c.ecx, edx: c.edx,
                               esi: c.esi, edi: c.edi, ebp: c.ebp };
            for (const k in regsList) {
              try {
                const v = regsList[k];
                const p = (typeof v === 'number') ? ptr(v) : v;
                if (!p || p.isNull()) continue;
                const at = p.toInt32() >>> 0;
                const blk = safeRead(at, 0x120);
                const ent = { at: p.toString(), hex: u8hex(blk.bytes, 0xa0), bad: blk.bad };
                // 把 [ecx+0x90/0x94/0x98] 三个字段单独取出来，方便直接读
                if (k === 'ecx' && blk.bad === 0) {
                  const b = blk.bytes;
                  ent.head = hx(b[0x90] | (b[0x91] << 8) | (b[0x92] << 16) | (b[0x93] << 24));
                  ent.tail = hx(b[0x94] | (b[0x95] << 8) | (b[0x96] << 16) | (b[0x97] << 24));
                  ent.cap = hx(b[0x98] | (b[0x99] << 8) | (b[0x9a] << 16) | (b[0x9b] << 24));
                }
                mem[k] = ent;
              } catch (e) {}
            }
          }
          logEv({ ev: 'EXC', type: d.type, fault: nreg(d.address), pc: nreg(c.pc), at: sym(c.pc),
                  tid: tidNow(),
                  regs: { eax: nreg(c.eax), ebx: nreg(c.ebx), ecx: nreg(c.ecx), edx: nreg(c.edx),
                          esi: nreg(c.esi), edi: nreg(c.edi), ebp: nreg(c.ebp), esp: nreg(c.sp) },
                  code: (function () { try { return hexOf(c.pc.sub(16), 40); } catch (e) { return null; } })(),
                  mem: Object.keys(mem).length ? mem : null,
                  stack: (function () { try { return hexOf(c.sp, 320); } catch (e) { return null; } })() });
        }
      } catch (e) { logErr('veh-log', e); }
      return false;                     // 继续正常传递
    });
    logEv({ ev: 'veh', ok: !!ok });
  } catch (e) { logErr('veh-install', e); }
}

hook('kernel32.dll', 'UnhandledExceptionFilter', {
  enter(a) {
    // a[0] = PEXCEPTION_POINTERS
    //   EXCEPTION_POINTERS { PEXCEPTION_RECORD ExceptionRecord; PCONTEXT ContextRecord; }
    //   EXCEPTION_RECORD   { DWORD Code; DWORD Flags; PEXCEPTION_RECORD Next;
    //                        PVOID Address; DWORD NumberParameters; ULONG_PTR Info[15]; }
    // x86 CONTEXT 关键偏移：Eax 0xB0, Ebp 0xB4, Eip 0xB8, Esp 0xC4, Ebx 0xA4,
    //                      Ecx 0xAC, Edx 0xA8, Esi 0xA0, Edi 0x9C
    // 只观察、不改任何返回值，所以不影响崩溃行为本身。
    const rec = {};
    try {
      const eps = a[0];
      const er = eps.readPointer();
      const ctx = eps.add(4).readPointer();
      rec.code = hx(er.readU32());
      rec.flags = er.add(4).readU32();
      rec.addr = er.add(0xc).readPointer().toString();
      rec.nparams = er.add(0x10).readU32();
      const n = Math.min(rec.nparams, 15);
      rec.params = [];
      for (let i = 0; i < n; i++) rec.params.push(er.add(0x14 + i * 4).readPointer().toString());
      rec.eip = ctx.add(0xb8).readPointer().toString();
      rec.esp = ctx.add(0xc4).readPointer().toString();
      rec.ebp = ctx.add(0xb4).readPointer().toString();
      rec.eax = ctx.add(0xb0).readPointer().toString();
      rec.ebx = ctx.add(0xa4).readPointer().toString();
      rec.ecx = ctx.add(0xac).readPointer().toString();
      rec.edx = ctx.add(0xa8).readPointer().toString();
      rec.esi = ctx.add(0xa0).readPointer().toString();
      rec.edi = ctx.add(0x9c).readPointer().toString();
      rec.eipSym = sym(ctx.add(0xb8).readPointer());
      rec.addrSym = sym(er.add(0xc).readPointer());
      rec.bt = btOf(ctx, 16);
    } catch (e) { rec.err = String(e); }
    logEv({ ev: 'UNHANDLED_EXCEPTION', rec: rec, tid: tidNow(), who: whoAmI() });
  },
});
hook('kernel32.dll', 'SetUnhandledExceptionFilter', {
  enter(a) { logEv({ ev: 'SetUnhandledExceptionFilter', fn: a[0].toString() }); },
});
hook('ntdll.dll', 'RtlUnhandledExceptionFilter', {
  enter(a) { logEv({ ev: 'RtlUnhandledExceptionFilter', bt: btOf(this.context, 12) }); },
});

/* ------------------------------------------------------------------ */
/* 内存：那些"不在模块里"的线程入口是哪来的                              */
/* ------------------------------------------------------------------ */
/* 注：VirtualAlloc/VirtualProtect 极其高频（一轮能刷 700+ 条），只在
 * --deep-trace 时开启，平时关掉以免日志被淹没。                          */
if (CFG.deepTrace) {
  hook('kernel32.dll', 'VirtualAlloc', {
    enter(a) { this.size = a[1].toInt32() >>> 0; this.prot = a[2].toInt32(); this.type = a[3].toInt32(); },
    leave(r) {
      if (!r.isNull()) logEv({ ev: 'VirtualAlloc', ret: r.toString(), size: this.size,
                               prot: hx(this.prot), type: hx(this.type), callers: btOf(this.context, 6) });
    },
  });
  hook('kernel32.dll', 'VirtualProtect', {
    enter(a) { this.p = a[0]; this.size = a[1].toInt32() >>> 0; this.newp = a[2].toInt32(); },
    leave(r) { logEv({ ev: 'VirtualProtect', addr: this.p.toString(), size: this.size, newProt: hx(this.newp) }); },
  });
}
hook('kernel32.dll', 'GetModuleFileNameW', {
  enter(a) { this.buf = a[1]; this.n = a[2].toInt32(); },
  leave(r) {
    const n = rdWStr(this.buf);
    if (n && !_gmnSeen[n]) { _gmnSeen[n] = 1; logEv({ ev: 'GetModuleFileNameW', name: n }); }
  },
});
hook('kernel32.dll', 'GetModuleFileNameA', {
  enter(a) { this.buf = a[1]; },
  leave(r) {
    const n = rdAStr(this.buf);
    if (n && !_gmnSeen[n]) { _gmnSeen[n] = 1; logEv({ ev: 'GetModuleFileNameA', name: n }); }
  },
});

/* ------------------------------------------------------------------ */
/* 网络 / 子进程：看它退出前到底想干什么                                */
/* ------------------------------------------------------------------ */
let _ws2Hooked = false;
function hookWs2() {
  if (_ws2Hooked) return;
  // ws2_32 上的 hook 与 Themida 的反虚拟机检查无关（实测 skip ws2 反而 3/3 触发），
  // 所以最小集模式下也允许用 CFG.hookWs2 打开网络追踪。
  if (SKIP_DLL['ws2_32.dll'] || (ONLY_COUNT && !CFG.hookWs2)) { _ws2Hooked = true; return; }
  let mod = null;
  try { mod = Process.getModuleByName('ws2_32.dll'); } catch (e) { return; }
  _ws2Hooked = true;
  const mk = (name, spec) => {
    try {
      const addr = mod.getExportByName(name);
      Interceptor.attach(addr, {
        onEnter(a) {
          this.__skip = false;
          if (__depth > 0 || inAgent(this.returnAddress)) { this.__skip = true; return; }
          try { __depth++; spec.enter.call(this, a); } catch (e) { logErr('enter:' + name, e); }
          finally { __depth--; }
        },
        onLeave(r) {
          if (this.__skip || __depth > 0) return;
          try { if (spec.leave) { __depth++; spec.leave.call(this, r); __depth--; } } catch (e) {}
        },
      });
      logEv({ ev: 'hooked', dll: 'ws2_32.dll', name: name });
    } catch (e) { logEv({ ev: 'noexport', mod: 'ws2_32.dll', name: name }); }
  };
  mk('WSAStartup', { enter(a) { logEv({ ev: 'WSAStartup', ver: hx(a[0].toInt32()) }); } });

  // 把 connect 的目标改写到本地 —— 客户端会去连外网游戏服
  // （实测 "60.206.12.127:30000"，每 3 秒重试，重试 11 次后放弃）。
  // 这个地址在客户端目录里搜不到明文/二进制，所以只能在 API 层改。
  // sockaddr_in: [+0]sin_family(2) [+2]sin_port(2,网络序) [+4]sin_addr(4)
  function redirectSockaddr(p) {
    if (!CFG.connectTo || !p || p.isNull()) return null;
    try {
      if (p.readU16() !== 2) return null;                     // 只处理 AF_INET
      const raw = p.add(2).readU16();
      const port = ((raw & 0xff) << 8) | (raw >> 8);          // 还原成主机序
      const ip = Array.from(new Uint8Array(p.add(4).readByteArray(4))).join('.');
      if (ip === '127.0.0.1') return null;                    // 本机其它服务不动
      p.add(2).writeU16(((CFG.connectToPort & 0xff) << 8) | (CFG.connectToPort >> 8));
      p.add(4).writeByteArray(CFG.connectToBytes);
      return { from: ip + ':' + port, to: CFG.connectTo };
    } catch (e) { return { err: String(e) }; }
  }
  mk('connect', {
    enter(a) {
      const r = redirectSockaddr(a[1]);
      logEv({ ev: 'connect', target: sockaddrStr(a[1]), redirected: r, sock: a[0].toInt32() });
    },
    leave(r) { logEv({ ev: 'connect.ret', ret: r.toInt32() }); },
  });
  mk('WSAConnect', {
    enter(a) {
      const r = redirectSockaddr(a[1]);
      logEv({ ev: 'WSAConnect', target: sockaddrStr(a[1]), redirected: r, sock: a[0].toInt32() });
    },
    leave(r) { logEv({ ev: 'WSAConnect.ret', ret: r.toInt32() }); },
  });
  mk('gethostbyname', { enter(a) { logEv({ ev: 'gethostbyname', name: rdAStr(a[0]) }); } });
  mk('getaddrinfo', { enter(a) { logEv({ ev: 'getaddrinfo', node: rdAStr(a[0]), service: rdAStr(a[1]) }); } });
  mk('GetAddrInfoW', { enter(a) { logEv({ ev: 'GetAddrInfoW', node: rdWStr(a[0]), service: rdWStr(a[1]) }); } });
  mk('send', {
    enter(a) {
      logEv({ ev: 'send', sock: a[0].toInt32(), len: a[2].toInt32(),
              data: hexOf(a[1], Math.min(a[2].toInt32(), 256)) });
    },
    leave(r) { logEv({ ev: 'send.ret', ret: r.toInt32() }); },
  });
  mk('recv', {
    enter(a) { this.b = a[1]; this.n = a[2].toInt32(); },
    leave(r) {
      const n = r.toInt32();
      logEv({ ev: 'recv', ret: n, data: (n > 0) ? hexOf(this.b, Math.min(n, 256)) : null });
    },
  });
  // WSASend/WSARecv 用 WSABUF { u32 len; char* buf; } 数组
  mk('WSASend', {
    enter(a) {
      let d = null;
      try { const n = Math.min(a[2].readU32(), 256); d = hexOf(a[1].add(4).readPointer(), n); } catch (e) {}
      logEv({ ev: 'WSASend', sock: a[0].toInt32(), data: d });
    },
  });
  mk('WSARecv', { enter(a) { this.b = a[1]; }, leave(r) { logEv({ ev: 'WSARecv', ret: r.toInt32() }); } });
}
hookWs2();

hook('ntdll.dll', 'LdrLoadDll', {
  enter(a) {
    const n = readUnicodeString(a[2]);
    if (n) {
      const isShell = /acopcshell/i.test(n);
      logEv({ ev: 'LdrLoadDll', name: n, tid: tidNow(), bt: isShell ? btOf(this.context, 12) : undefined });
      if (n.toLowerCase().indexOf('ws2_32') >= 0) this.needWs2 = true;
    }
  },
  leave() { if (this.needWs2) hookWs2(); },
});

hook('kernel32.dll', 'CreateProcessW', {
  enter(a) { logEv({ ev: 'CreateProcessW', app: rdWStr(a[0]), cmd: rdWStr(a[1]) }); },
});
hook('kernel32.dll', 'CreateProcessA', {
  enter(a) { logEv({ ev: 'CreateProcessA', app: rdAStr(a[0]), cmd: rdAStr(a[1]) }); },
});
hook('kernel32.dll', 'WinExec', {
  enter(a) { logEv({ ev: 'WinExec', cmd: rdAStr(a[0]), show: a[1].toInt32() }); },
});
hook('shell32.dll', 'ShellExecuteW', {
  enter(a) { logEv({ ev: 'ShellExecuteW', file: rdWStr(a[2]), params: rdWStr(a[3]) }); },
});
hook('kernel32.dll', 'LoadLibraryW', {
  enter(a) { this.p = rdWStr(a[0]); },
  leave(r) { handleLibLoad('LoadLibraryW', this.p, r, this.context); },
});
hook('kernel32.dll', 'LoadLibraryExW', {
  enter(a) { this.p = rdWStr(a[0]); },
  leave(r) { handleLibLoad('LoadLibraryExW', this.p, r, this.context); },
});
hook('kernel32.dll', 'LoadLibraryA', {
  enter(a) { this.p = rdAStr(a[0]); },
  leave(r) { handleLibLoad('LoadLibraryA', this.p, r, this.context); },
});
// ACOPCShell.dll 已知导出名（从内嵌模块的字符串表里拿到的）
const SHELL_EXPORTS = ['InitAcopc', 'InitSystem', 'RegisterApi', 'IntegrityCheck', 'Release',
                       'Scan', 'SecurityCallApi', 'SetSpeedGearCallBack', 'UpdateScanEngineHdb',
                       'ZESecurityCallApi'];
function isShellProc(n) {
  if (!n) return false;
  const l = n.toLowerCase();
  return SHELL_EXPORTS.some(x => l === x.toLowerCase()) || l.indexOf('acopc') >= 0;
}
hook('kernel32.dll', 'GetProcAddress', {
  enter(a) {
    this.h = a[0]; this.n = rdAStr(a[1]); this.ord = (a[1].toInt32() >>> 0);
    let fakeHit = false;
    try { fakeHit = !!(FAKE_SHELL_HANDLE && this.h && this.h.toString() === FAKE_SHELL_HANDLE.toString()); } catch (e) {}
    this.hit = isShellProc(this.n) || fakeHit;
    this.mod = null;
    if (this.hit) { try { const m = Process.findModuleByAddress(this.h); this.mod = m ? m.name : null; } catch (e) {} }
  },
  leave(r) {
    if (this.hit) {
      logEv({ ev: 'GetProcAddress(shell)', name: this.n, ordinal: this.ord,
              h: this.h.toString(), mod: this.mod, ret: r.toString(), isNull: r.isNull() ? 1 : 0,
              tid: tidNow() });
    }
  },
});

/* ------------------------------------------------------------------ */
/* 定位 Themida 的反虚拟机弹窗：它不走 MessageBoxW，换个路子抓           */
/* ------------------------------------------------------------------ */
const GAME_MOD = (function () { try { return Process.getModuleByName('GundamOnline_CHINA.exe'); } catch (e) { return null; } })();

// exe 镜像里 .vmp0 / ohjicybf / esllbfpk 三段（壳自己的代码）的偏移范围
function inThemida(a) {
  try {
    if (!GAME_MOD || !a) return false;
    const off = a.sub(GAME_MOD.base).toInt32() >>> 0;
    return off >= 0xE10000 && off <= 0xEEE000;
  } catch (e) { return false; }
}
logEv({ ev: 'game_mod', base: GAME_MOD ? GAME_MOD.base.toString() : null,
        size: GAME_MOD ? GAME_MOD.size : null,
        end: GAME_MOD ? GAME_MOD.base.add(GAME_MOD.size).toString() : null,
        resSlot: GAME_MOD ? GAME_MOD.base.add(0x1162058).toString() : null,
        themidaRange: GAME_MOD ? [GAME_MOD.base.add(0xE10000).toString(),
                                  GAME_MOD.base.add(0xEEE000).toString()] : null });

// 弹窗家族：凡是建窗口/弹框都记下来，附回溯
hook('user32.dll', 'MessageBoxIndirectW', {
  enter(a) { logEv({ ev: 'MessageBoxIndirectW', tid: tidNow(), bt: btOf(this.context, 14) }); },
});
hook('user32.dll', 'DialogBoxParamW', {
  enter(a) { logEv({ ev: 'DialogBoxParamW', templ: a[1].toString(), bt: btOf(this.context, 12) }); },
});
hook('user32.dll', 'CreateWindowExW', {
  enter(a) {
    this.cls = rdWStr(a[1]); this.title = rdWStr(a[2]);
    const thermo = inThemida(this.returnAddress);
    if (thermo || (this.cls && /#32770|Themida/i.test(this.cls)) ||
        (this.title && /Themida|Virtual Machine/i.test(this.title))) {
      logEv({ ev: 'CreateWindowExW', cls: this.cls, title: this.title,
              caller: sym(this.returnAddress), fromThemida: thermo ? 1 : 0,
              bt: btOf(this.context, 12) });
    }
  },
});
hook('user32.dll', 'CreateWindowExA', {
  enter(a) {
    this.cls = rdAStr(a[1]); this.title = rdAStr(a[2]);
    if ((this.cls && /#32770|Themida/i.test(this.cls)) ||
        (this.title && /Themida|Virtual Machine/i.test(this.title))) {
      logEv({ ev: 'CreateWindowExA', cls: this.cls, title: this.title,
              caller: sym(this.returnAddress), bt: btOf(this.context, 12) });
    }
  },
});

// 反虚拟机常见的探测入口：只在"壳自己的代码"调用时记录，避免刷屏
function probeHook(dll, name, spec) {
  hook(dll, name, {
    enter(a) {
      const fromT = inThemida(this.returnAddress);
      this.__t = fromT;
      if (!fromT) return;
      logEv({ ev: 'VM_PROBE:' + name, args: spec ? spec(a) : null,
              caller: sym(this.returnAddress), tid: tidNow(), bt: btOf(this.context, 10) });
    },
    leave(r) {
      if (this.__t) logEv({ ev: 'VM_PROBE_RET:' + name, ret: r.toString() });
    },
  });
}
probeHook('ntdll.dll', 'NtQuerySystemInformation', a => 'class=' + hx(a[0].toInt32()));
probeHook('kernel32.dll', 'GetSystemFirmwareTable', a => 'sig=' + hx(a[0].toInt32()) + ' id=' + hx(a[1].toInt32()));
probeHook('kernel32.dll', 'EnumSystemFirmwareTables', a => 'sig=' + hx(a[0].toInt32()));
probeHook('kernel32.dll', 'IsProcessorFeaturePresent', a => 'feat=' + a[0].toInt32());
probeHook('ntdll.dll', 'NtQueryInformationProcess', a => 'class=' + hx(a[1].toInt32()));

// 壳若去读 DeviceGuard/虚拟化相关注册表，也记一笔
hook('advapi32.dll', 'RegOpenKeyExW', {
  enter(a) {
    const p = rdWStr(a[1]);
    if (p && /deviceguard|virtualization|hyper-?v|vmware|virtualbox|systembios/i.test(p)) {
      logEv({ ev: 'RegOpenKey', path: p, caller: sym(this.returnAddress) });
    }
  },
});
hook('advapi32.dll', 'RegQueryValueExW', {
  enter(a) {
    const p = rdWStr(a[1]);
    if (p && /enablevirtualization|hypervisor|virtual/i.test(p)) {
      logEv({ ev: 'RegQueryValue', name: p, caller: sym(this.returnAddress) });
    }
  },
});

/* ------------------------------------------------------------------ */
logEv({ ev: 'ready', arch: Process.arch, ptrSize: Process.pointerSize, pid: Process.id,
        fake: CFG.fake, dumpDir: CFG.dumpDir, deepTrace: !!CFG.deepTrace,
        agentMods: AGENT_MODS.map(function (m) { return m.name + '@' + m.base.toString(); }) });
