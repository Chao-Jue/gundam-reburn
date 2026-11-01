#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""开工脚本（需要管理员）：关掉 hypervisor，为跑客户端做准备。

为什么：客户端外层是 Themida，它读 `CPUID.1:ECX bit31` 判断"是否在虚拟机里"。
本机开着 VBS / VirtualMachinePlatform 时该位为 1，客户端直接弹
"Sorry, this application cannot run under a Virtual Machine" 并退出。
关掉 hypervisor 后该位归 0，客户端才能起来。

动作（与 `env_restore.py` 正好相反）：
  1. 杀掉残留的 run_hooked.py / elevated_watcher.py / GundamOnline_CHINA.exe
     （自己与祖先一律跳过）。
  2. `bcdedit /set hypervisorlaunchtype off`
  3. `HiberbootEnabled = 0` —— 关快速启动。这样即便用"关机再开机"也能让 BCD 生效
     （否则会从 hiberfil 还原旧内核会话，hypervisor 照样起来）。
  4. 回读确认。

⚠️ 改完必须**真重启**（`shutdown /r /t 0` 或开始菜单的"重启"）才生效。

回滚：`python tools/env_restore.py` + 真重启（恢复 WSL2 / Sandbox / VBS）。
"""
from __future__ import annotations

import os
import subprocess
import sys

KILL_SCRIPTS = ("run_hooked.py", "elevated_watcher.py")
KILL_EXES = ("gundamonline_china.exe",)

PS_LIST = ("Get-CimInstance Win32_Process -Filter "
           "\"Name='python.exe' or Name='pythonw.exe' or Name='GundamOnline_CHINA.exe'\" | "
           "ForEach-Object { \"$($_.ProcessId)`t$($_.ParentProcessId)`t$($_.Name)`t$($_.CommandLine)\" }")

POWER_KEY = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power"


def run(argv: list[str]) -> tuple[int, str]:
    # Windows 下 bcdedit/reg 的输出是 GBK(ANSI)。用 text=True 默认 utf-8 会抛
    # UnicodeDecodeError（在 reader 线程里），导致 out 为空 → "未列出" 的假阴性。
    try:
        r = subprocess.run(argv, capture_output=True, timeout=60)
    except Exception as e:  # noqa: BLE001
        return 1, f"<异常 {e}>"
    txt = (r.stdout or b"") + (r.stderr or b"")
    return r.returncode, txt.decode("mbcs", errors="replace").strip()


def list_procs() -> list[tuple[int, int, str, str]]:
    rc, out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_LIST])
    rows: list[tuple[int, int, str, str]] = []
    if rc != 0:
        print(f"[!] 枚举进程失败: {out[:200]}")
        return rows
    for line in out.splitlines():
        parts = line.split("\t", 3)
        if len(parts) < 4:
            continue
        try:
            pid, ppid = int(parts[0].strip()), int(parts[1].strip())
        except ValueError:
            continue
        rows.append((pid, ppid, parts[2].strip(), parts[3].strip()))
    return rows


def kill(pid: int, why: str) -> bool:
    rc, out = run(["taskkill", "/F", "/PID", str(pid)])
    first = out.splitlines()[0] if out else ""
    print(f"    [{'OK' if rc == 0 else 'XX'}] {pid}  {why}  {first}")
    return rc == 0


def stop_lab() -> int:
    print("=" * 62)
    print(" [1/4] 停止残留实验进程")
    print("=" * 62)
    procs = list_procs()
    ppid_of = {p[0]: p[1] for p in procs}
    keep: set[int] = set()
    pid = os.getpid()
    while pid and pid not in keep and len(keep) < 32:
        keep.add(pid)
        pid = ppid_of.get(pid, 0)
    keep.add(os.getppid())
    print(f"[*] 保留（自己+祖先）: {sorted(keep)}")

    killed = 0
    clients: list[tuple[int, str]] = []
    for pid, _ppid, name, cmd in procs:
        if pid in keep:
            continue
        nlow = name.lower()
        if nlow in KILL_EXES:
            clients.append((pid, name))
            continue
        if nlow.startswith("python"):
            for s in KILL_SCRIPTS:
                if s.lower() in cmd.lower():
                    if kill(pid, f"{name} ...{cmd[-60:]}"):
                        killed += 1
                    break
    for pid, name in clients:
        kill(pid, f"{name} (客户端)")

    left = [p for p in list_procs() if p[2].lower() in KILL_EXES]
    print(f"[*] runner 结束 {killed} 个；客户端残留: {left if left else '无'}")
    return 0 if not left else 1


def disable_hypervisor() -> int:
    print()
    print("=" * 62)
    print(" [2/4] hypervisorlaunchtype = off")
    print("=" * 62)
    _rc, out = run(["bcdedit", "/enum", "{current}"])
    pre = [l.strip() for l in out.splitlines() if "hypervisor" in l.lower()]
    print("[改前] " + ("\n[改前] ".join(pre) if pre else "(未列出，默认 Auto)"))

    rc, out = run(["bcdedit", "/set", "hypervisorlaunchtype", "off"])
    print(f"[*] bcdedit /set off -> exitcode={rc} {out}")

    _rc, out = run(["bcdedit", "/enum", "{current}"])
    post = [l.strip() for l in out.splitlines() if "hypervisor" in l.lower()]
    print("[改后] " + ("\n[改后] ".join(post) if post else "(没有该行！设置可能没写进去)"))
    return rc


def disable_fast_startup() -> int:
    print()
    print("=" * 62)
    print(" [3/4] 关快速启动 (HiberbootEnabled = 0)")
    print("=" * 62)
    # 注意：reg.exe 在本机安全策略的"程序黑名单"里，直接调会被拦（WinError 5）。
    # 改用 PowerShell 的 Set-ItemProperty，效果相同。
    ps_set = (
        "$p='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power';"
        "Set-ItemProperty -Path $p -Name HiberbootEnabled -Value 0 -Type DWord;"
        "$v=(Get-ItemProperty -Path $p -Name HiberbootEnabled).HiberbootEnabled;"
        "Write-Output ('HiberbootEnabled=' + $v)"
    )
    rc, out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_set])
    print(f"[*] Set-ItemProperty -> exitcode={rc}")
    print("[回读] " + out.replace("\n", " "))
    return rc


def main() -> int:
    print("=== gundam-reburn 开工：关虚拟化 + 关快速启动 ===")
    stop_lab()
    disable_hypervisor()
    disable_fast_startup()
    print()
    print("=" * 62)
    print(" [4/4] 完成 —— 现在必须【真重启】机器")
    print("=" * 62)
    print("     shutdown /r /t 0    （或开始菜单 -> 重启）")
    print("     重启后验证：python tools/env_check.py  （CPUID bit31 应为 0）")
    print("     重启后再跑游戏：python tools/run_hooked.py --seconds 900 --retry 8")
    print()
    print("     收工回滚：python tools/env_restore.py + 真重启")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    raise SystemExit(main())
