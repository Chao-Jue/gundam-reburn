#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""清理上一轮实验残留的【提权】进程（必须在管理员下运行）。

为什么需要它：
    `elevated_watcher.py --batch` 起来的 run_hooked.py 是提权的，普通终端
    `taskkill` 会报"拒绝访问"，于是换实验参数时旧进程清不掉，后果是
      1) 旧的 run_hooked.py 占着 `server/hook_log.txt`，新轮 0.4s 就崩；
      2) 旧客户端还在跑 —— 违反项目约定「同一时间只允许一个客户端」。

本脚本在提权批次里作为**第一条作业**跑，然后第二条才是真正的实验。
自己（以及自己的父进程，也就是当前这个执行器）不会被杀。
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK_LOG = ROOT / "server" / "hook_log.txt"

# 只杀这些：别的 python（world_sniff / cn_server / fake_http）要留着。
# ⚠️ 绝不能把 elevated_watcher.py 放进名单：killstale 自己就是被它起来的孩子，
#    一次实测里它把父进程（执行器）一起杀了，整棵批次树当场消失。
#    执行器的清理交给 run_hooked.py 里的 kill_stale_runners()。
KILL_SCRIPTS = ("run_hooked.py",)
KILL_EXES = ("gundamonline_china.exe",)


def list_procs() -> list[tuple[int, int, str, str]]:
    """(pid, ppid, name, cmdline)。Win11 上 wmic 常常没了，用 CIM。"""
    filt = ("Name='python.exe' or Name='pythonw.exe' "
            "or Name='GundamOnline_CHINA.exe'")
    ps = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
          f"Get-CimInstance Win32_Process -Filter \"{filt}\" | "
          "ForEach-Object { \"$($_.ProcessId)`t$($_.ParentProcessId)`t$($_.Name)`t$($_.CommandLine)\" }"]
    try:
        r = subprocess.run(ps, capture_output=True, text=True, timeout=60)
    except Exception as e:  # noqa: BLE001
        print(f"[!] 枚举进程失败: {e}")
        return []
    rows: list[tuple[int, int, str, str]] = []
    for line in (r.stdout or "").splitlines():
        parts = line.split("\t", 3)
        if len(parts) < 4:
            continue
        try:
            pid, ppid = int(parts[0].strip()), int(parts[1].strip())
        except ValueError:
            continue
        rows.append((pid, ppid, parts[2].strip(), parts[3].strip()))
    return rows


def pid_alive(pid: int) -> bool:
    try:
        r = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                           capture_output=True, text=True, timeout=30)
        return str(pid) in (r.stdout or "")
    except Exception:  # noqa: BLE001
        return False


def kill(pid: int, why: str) -> bool:
    try:
        r = subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, text=True, timeout=30)
    except Exception as e:  # noqa: BLE001
        print(f"    [X] {pid} taskkill 异常: {e}")
        return False
    out = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()
    ok = r.returncode == 0
    print(f"    [{'OK' if ok else 'XX'}] {pid}  {why}  {out[0] if out else ''}")
    return ok


def main() -> int:
    me = os.getpid()
    print(f"[*] killstale pid={me}")

    procs = list_procs()
    # 自己 + 全部祖先进程：一个都不许杀（踩过坑）。
    ppid_of = {p[0]: p[1] for p in procs}
    keep = set()
    pid = me
    while pid and pid not in keep and len(keep) < 32:
        keep.add(pid)
        pid = ppid_of.get(pid, 0)
    try:
        keep.add(os.getppid())
    except Exception:  # noqa: BLE001
        pass
    print(f"[*] 保留（自己+祖先）: {sorted(keep)}")

    killed = 0
    seen = 0
    for pid, _ppid, name, cmd in procs:
        nlow = name.lower()
        if pid in keep:
            print(f"    [--] {pid} 跳过（自己/祖先）")
            continue
        seen += 1
        if nlow in KILL_EXES:
            if kill(pid, f"{name} (客户端)"):
                killed += 1
            continue
        if nlow.startswith("python"):
            for s in KILL_SCRIPTS:
                if s.lower() in cmd.lower():
                    if kill(pid, f"{name} ...{cmd[-80:]}"):
                        killed += 1
                    break

    print(f"[*] 扫描 {seen} 个候选进程，结束 {killed} 个")

    # 旧的 hook_log.txt 可能被残留句柄锁着，顺手清掉（失败不算问题）。
    try:
        if HOOK_LOG.exists():
            HOOK_LOG.unlink()
            print(f"[*] 已删除 {HOOK_LOG}")
    except Exception as e:  # noqa: BLE001
        print(f"[!] 删除 hook_log.txt 失败（忽略）: {e}")

    # 复核：客户端必须干净。
    left = [p for p in list_procs() if p[2].lower() in KILL_EXES]
    if left:
        print(f"[!] 仍有客户端残留: {left}")
        return 1
    print("[*] 客户端已清空，可以开新一轮。")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    raise SystemExit(main())
