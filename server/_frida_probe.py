"""探测 frida 能否从 64 位宿主注入 32 位 (WOW64) 进程。

路线 B 的前提。用 C:\\Windows\\SysWOW64\\notepad.exe（32 位）做靶子。
"""

from __future__ import annotations

import sys
import time

import frida

JS = r"""
send({ ev: 'hello', arch: Process.arch, ptrsize: Process.pointerSize,
       platform: Process.platform, pid: Process.id });
try {
  const m = Process.getModuleByName('kernel32.dll');
  send({ ev: 'module', name: m.name, base: m.base.toString(), size: m.size });
} catch (e) { send({ ev: 'module_err', err: String(e) }); }
try {
  const addr = Module.getExportByName('kernel32.dll', 'CreateFileW');
  send({ ev: 'export', name: 'CreateFileW', addr: addr.toString() });
  Interceptor.attach(addr, {
    onEnter(a) { send({ ev: 'CreateFileW', path: (function(){try{return a[0].readUtf16String();}catch(e){return null;}})() }); },
  });
} catch (e) { send({ ev: 'hook_err', err: String(e) }); }
send({ ev: 'ready' });
"""


def main() -> int:
    target = r"C:\Windows\SysWOW64\notepad.exe"
    print("frida version:", frida.__version__)
    device = frida.get_local_device()
    print("device:", device)
    print("spawn:", target)
    pid = device.spawn(target)
    print("pid:", pid)
    session = device.attach(pid)
    print("attached")

    script = session.create_script(JS)
    seen = []

    def on_message(msg, data):
        seen.append(msg)
        print("MSG:", msg)

    script.on("message", on_message)
    script.load()
    device.resume(pid)
    time.sleep(2.0)

    # 触发一次 CreateFileW，看 hook 是否真的生效
    print("--- 触发文件操作 ---")
    try:
        import ctypes

        ctypes.windll.kernel32.CreateFileW("C:\\Windows\\win.ini", 0, 0, None, 3, 0, None)
    except Exception as e:
        print("trigger err", e)
    time.sleep(1.5)

    try:
        session.detach()
    except Exception:
        pass
    try:
        device.kill(pid)
    except Exception:
        pass
    print("\n== 收到", len(seen), "条消息 ==")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    raise SystemExit(main())
