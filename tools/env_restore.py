#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""收工脚本（必须在管理员下运行）：停掉实验进程 + 恢复虚拟化环境。

动作：
  1. 杀 掉 run_hooked.py / elevated_watcher.py / GundamOnline_CHINA.exe
     （自己与自己的祖先进程一律跳过，避免"杀掉执行器把整棵树带走"的老坑）。
  2. `bcdedit /set hypervisorlaunchtype auto` —— 把 2026-10-14 为跑游戏而关掉的
     hypervisor 启动项改回默认，WSL2 / Sandbox / VBS 需要它。
  3. 回读 bcdedit 确认，并打印 HiberbootEnabled。

⚠️ 改完必须**真重启**（`shutdown /r /t 0` 或开始菜单的"重启"）才生效；
   关机再按电源键在快速启动开着时会从 hiberfil 还原旧内核会话，不按 BCD 初始化。
   本脚本不动 HiberbootEnabled（保持 fix_hypervisor_off.cmd 设的 0，这样 BCD 改动
   在"关机再开机"时也能生效）。

回滚（想再跑游戏）：`bcdedit /set hypervisorlaunchtype off` + 真重启，
或直接双击 `tools/fix_hypervisor_off.cmd`。
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


def run(argv: list[str]) -> tuple[int, str]:
    # bcdedit/reg 输出是 GBK(ANSI)；text=True 默认 utf-8 会在 reader 线程里
    # 抛 UnicodeDecodeError，导致读不到结果（假阴性）。统一按 mbcs 解。
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
    print(" [1/3] 停止实验进程")
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

    # 先杀 runner，再杀客户端 —— 否则 run_hooked 的 --retry 会立刻把客户端再拉起来。
    killed_runners = 0
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
                    if kill(pid, f"{name} ...{cmd[-70:]}"):
                        killed_runners += 1
                    break
    for pid, name in clients:
        kill(pid, f"{name} (客户端)")

    left = [p for p in list_procs() if p[2].lower() in KILL_EXES]
    print(f"[*] runner 结束 {killed_runners} 个；客户端残留: {left if left else '无'}")
    return 0 if not left else 1


def restore_hypervisor() -> int:
    print()
    print("=" * 62)
    print(" [2/3] 恢复 hypervisorlaunchtype = auto")
    print("=" * 62)
    rc, out = run(["bcdedit", "/enum", "{current}"])
    print("[改前] " + "\n[改前] ".join(
        l.strip() for l in out.splitlines() if "hypervisor" in l.lower()) or "[改前] (未列出)")
    rc, out = run(["bcdedit", "/set", "hypervisorlaunchtype", "auto"])
    print(f"[*] bcdedit /set exitcode={rc}: {out}")
    rc, out = run(["bcdedit", "/enum", "{current}"])
    lines = [l.strip() for l in out.splitlines() if "hypervisor" in l.lower()]
    print("[改后] " + ("\n[改后] ".join(lines) if lines else "(没有 hypervisorlaunchtype 行 = 默认 Auto，正常)"))
    rc, out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                   "$p='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power';"
                   "try{$v=(Get-ItemProperty -Path $p -Name HiberbootEnabled).HiberbootEnabled;"
                   "Write-Output ('HiberbootEnabled=' + $v)}catch{Write-Output 'HiberbootEnabled=<none>'}",
                   ])
    print("[快速启动] " + out.replace("\n", " "))
    return rc


def main() -> int:
    print("=== gundam-reburn 收工：停实验 + 恢复虚拟化 ===")
    stop_lab()
    restore_hypervisor()
    print()
    print("=" * 62)
    print(" [3/3] 完成 —— 现在请【真重启】机器")
    print("=" * 62)
    print("     shutdown /r /t 0    （或开始菜单 -> 重启）")
    print("     不要用'关机再开机'：快速启动开着时会从 hiberfil 还原，BCD 不生效。")
    print("     重启后验证：python tools/env_check.py  （CPUID bit31 应重新为 1）")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    raise SystemExit(main())
