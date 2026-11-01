#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""常驻提权执行器：UAC 只点一次，之后可以反复跑需要管理员权限的命令。

背景：项目的每次实验（run_hooked.py / plain_launch.py --elevate /
drv_load_probe.py）都要管理员权限，一轮一点 UAC 太慢。这个脚本提权后常驻，
轮询固定目录里的作业文件，执行完把输出写回去。

协议（目录默认 server/hook_runs/）：
    写 _job.txt    -> 里面是一行命令行（相对 tools/ 或绝对路径）
    等 _job.done   -> 出现即表示执行完毕，输出在 _job.out
    写 _job.stop   -> 让执行器退出

用法：
    # 1) 提权启动执行器（只需一次 UAC），它会一直待命
    python tools/elevated_watcher.py

    # 2) 另开一个普通终端，提交作业
    python tools/elevated_watcher.py --submit "run_hooked.py --seconds 30"
    #    默认会等作业结束并打印输出

安全约束：只允许执行 tools/ 下已有的 .py，或者以 python 解释器开头的命令；
不接受任意 shell 重定向/管道，避免把它变成万能提权后门。
"""
from __future__ import annotations

import argparse
import ctypes
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
JOBDIR = ROOT / "server" / "hook_runs"
JOB = JOBDIR / "_job.txt"
OUT = JOBDIR / "_job.out"
DONE = JOBDIR / "_job.done"
STOP = JOBDIR / "_job.stop"
LOG = JOBDIR / "_watcher.log"
# 批处理结束标记。默认沿用 _batch.done；但每轮运行会传一个唯一名字
# （_batch.done.<pid>），否则"上一轮执行器刚写的 _batch.done"会让新一轮的
# 包装进程误判完成而提前退出 —— 一提权整棵树就被作业对象回收。
DONE_MARKER = JOBDIR / "_batch.done"


def wlog(msg: str) -> None:
    """执行器是独立控制台，看不到它的输出；同时写一份日志方便排查。"""
    try:
        JOBDIR.mkdir(parents=True, exist_ok=True)
        with LOG.open("a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    except Exception:
        pass

ALLOWED_EXTRA = {"run_hooked.py", "plain_launch.py", "drv_load_probe.py", "clean_cps.py",
                 "capture_cps.py", "env_check.py", "elevate_run.py", "killstale.py",
                 "hosts_up.py", "env_restore.py", "env_prepare_game.py",
                 "page_prot_test.py", "tables_probe.py", "pilot_call.py",
                 "vt_probe.py"}
FORBIDDEN_CHARS = set("|&;><`$()")

# 单条作业的最长运行时间。有些实验（让客户端停在登录界面等人操作）需要远超 900s，
# 用命令行 --timeout 覆盖。
JOB_TIMEOUT = 900.0


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate_self(extra: list[str] | None = None, wait: bool = False,
                 exit_after: bool = True) -> None:
    """不是管理员就 runas 起一个新实例（控制台窗口可见，方便看日志）。

    wait=True 时父进程会一直等子进程结束 —— 这一步很关键：调用方（比如
    agent 的 shell）往往在作业对象里，父进程一退出，Windows 会把同作业里的
    提权子进程一起回收，导致"执行器刚起来就没了"。
    """
    if is_admin():
        return
    class _SEI(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_ulong), ("fMask", ctypes.c_ulong),
            ("hwnd", ctypes.c_void_p),
            ("lpVerb", ctypes.c_wchar_p), ("lpFile", ctypes.c_wchar_p),
            ("lpParameters", ctypes.c_wchar_p), ("lpDirectory", ctypes.c_wchar_p),
            ("nShow", ctypes.c_int), ("hInstApp", ctypes.c_void_p),
            ("lpIDList", ctypes.c_void_p), ("lpClass", ctypes.c_wchar_p),
            ("hkeyClass", ctypes.c_void_p), ("dwHotKey", ctypes.c_ulong),
            ("hIcon", ctypes.c_void_p), ("hProcess", ctypes.c_void_p),
        ]
    sei = _SEI()
    sei.cbSize = ctypes.sizeof(_SEI)
    sei.fMask = 0x00000040 | (0x00000100 if not wait else 0)
    #                          NOCLOSEPROCESS   (不设 NOASYNC 才拿得到 hProcess)
    sei.fMask = 0x00000040
    sei.lpVerb = "runas"
    sei.lpFile = sys.executable
    argv = [str(Path(__file__).resolve())] + (extra or [])
    sei.lpParameters = subprocess.list2cmdline(argv)
    sei.lpDirectory = str(ROOT)
    sei.nShow = 1
    print("[*] 需要管理员权限，正在提权……（点一次“是”，之后就不用再点了）", flush=True)
    wlog("请求提权 (ShellExecuteExW runas): " + sei.lpParameters)
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        err = ctypes.get_last_error()
        print(f"[X] 提权失败（错误码 {err}）")
        wlog(f"提权失败 err={err}")
        raise SystemExit(3)
    if wait and sei.hProcess:
        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_void_p(sei.hProcess), 0xFFFFFFFF)
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(ctypes.c_void_p(sei.hProcess),
                                                  ctypes.byref(code))
        print(f"[*] 提权子进程结束，退出码 {code.value}", flush=True)
    if exit_after:
        raise SystemExit(0)
    return


def run_batch(path: Path) -> int:
    """批处理：一次提权，连着跑多条作业，每条输出写 _batch_<i>.out。"""
    lines = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()]
    cmds = [ln for ln in lines if ln and not ln.startswith("#")]
    wlog(f"批处理启动 pid={os.getpid()} 共 {len(cmds)} 条")
    print(f"[*] 批处理共 {len(cmds)} 条作业", flush=True)
    for i, cmd in enumerate(cmds, 1):
        out = JOBDIR / f"_batch_{i}.out"
        print(f"\n{'=' * 68}\n[{i}/{len(cmds)}] {cmd}\n{'=' * 68}", flush=True)
        wlog(f"[{i}/{len(cmds)}] {cmd}")
        ok, why = check_command(cmd)
        if not ok:
            out.write_text(f"[X] 拒绝执行：{why}\n", encoding="utf-8")
            print(f"[X] 拒绝执行：{why}", flush=True)
            continue
        parts = [p.strip('"') for p in shlex.split(cmd, posix=False)]
        if os.path.basename(parts[0]).lower() in ("python.exe", "python"):
            parts = parts[1:]
        script = Path(parts[0])
        if not script.exists():
            script = TOOLS / script
        argv = [sys.executable, str(script)] + parts[1:]
        t0 = time.time()
        try:
            with out.open("w", encoding="utf-8", errors="replace") as fh:
                p = subprocess.run(argv, cwd=str(ROOT), stdout=fh,
                                   stderr=subprocess.STDOUT, timeout=JOB_TIMEOUT)
            code = p.returncode
        except subprocess.TimeoutExpired:
            code = "TIMEOUT"
        except Exception as e:  # noqa: BLE001
            code = f"ERROR {e}"
        print(f"[<] code={code} 用时 {time.time() - t0:.1f}s -> {out.name}", flush=True)
        wlog(f"[<] code={code} 用时 {time.time() - t0:.1f}s -> {out.name}")
    (JOBDIR / "_batch.done").write_text("done", encoding="utf-8")
    if DONE_MARKER != JOBDIR / "_batch.done":
        DONE_MARKER.write_text("done", encoding="utf-8")
    return 0


def check_command(cmd: str) -> tuple[bool, str]:
    """只放行 tools/ 下的脚本，避免变成任意提权后门。"""
    if any(c in FORBIDDEN_CHARS for c in cmd):
        return False, "命令里不允许出现 | & ; > < ` $ ( ) 等 shell 字符"
    try:
        parts = shlex.split(cmd, posix=False)
    except Exception as e:  # noqa: BLE001
        return False, f"无法解析命令: {e}"
    if not parts:
        return False, "空命令"
    parts = [p.strip('"') for p in parts]
    if os.path.basename(parts[0]).lower() not in ("python.exe", "python"):
        # 只认脚本名，解释器由我们决定
        script = parts[0]
    else:
        if len(parts) < 2:
            return False, "缺脚本名"
        script = parts[1]
        parts = parts[1:]
    name = os.path.basename(script).lower()
    if name not in ALLOWED_EXTRA:
        return False, f"只允许执行: {', '.join(sorted(ALLOWED_EXTRA))}"
    return True, ""


def run_job(cmd: str) -> None:
    ok, why = check_command(cmd)
    if not ok:
        OUT.write_text(f"[X] 拒绝执行：{why}\n", encoding="utf-8")
        return
    parts = shlex.split(cmd, posix=False)
    parts = [p.strip('"') for p in parts]
    if os.path.basename(parts[0]).lower() in ("python.exe", "python"):
        parts = parts[1:]
    script = Path(parts[0])
    if not script.exists():
        script = TOOLS / script
    argv = [sys.executable, str(script)] + parts[1:]
    print(f"\n[>] 执行: {subprocess.list2cmdline(argv)}", flush=True)
    t0 = time.time()
    try:
        with OUT.open("w", encoding="utf-8", errors="replace") as fh:
            p = subprocess.run(argv, cwd=str(ROOT), stdout=fh, stderr=subprocess.STDOUT,
                               timeout=JOB_TIMEOUT)
        code = p.returncode
    except subprocess.TimeoutExpired:
        code = "TIMEOUT"
    except Exception as e:  # noqa: BLE001
        code = f"ERROR {e}"
    msg = f"\n[<] 结束 code={code} 用时 {time.time() - t0:.1f}s\n"
    print(msg, flush=True)
    with OUT.open("a", encoding="utf-8") as fh:
        fh.write(msg)


def watch() -> int:
    JOBDIR.mkdir(parents=True, exist_ok=True)
    wlog(f"执行器启动 pid={os.getpid()} is_admin={is_admin()} exe={sys.executable}")
    print("=" * 68)
    print(" 常驻提权执行器已就绪（管理员）")
    print(f" 作业目录: {JOBDIR}")
    print(f" 提交:     python tools/elevated_watcher.py --submit \"run_hooked.py --seconds 30\"")
    print(f" 停止:     python tools/elevated_watcher.py --stop")
    print("=" * 68, flush=True)
    last = None
    while True:
        if STOP.exists():
            print("[*] 收到 _job.stop，退出。", flush=True)
            try:
                STOP.unlink()
            except Exception:
                pass
            return 0
        if JOB.exists():
            try:
                mtime = JOB.stat().st_mtime
                if mtime != last:
                    last = mtime
                    cmd = JOB.read_text(encoding="utf-8").strip()
                    for p in (DONE, OUT):
                        if p.exists():
                            p.unlink()
                    if cmd:
                        run_job(cmd)
                    DONE.write_text("done", encoding="utf-8")
            except Exception as e:  # noqa: BLE001
                print(f"[!] 作业处理失败: {e}", flush=True)
        time.sleep(0.4)


def submit(cmd: str, wait: bool) -> int:
    JOBDIR.mkdir(parents=True, exist_ok=True)
    if DONE.exists():
        try:
            DONE.unlink()
        except Exception:
            pass
    JOB.write_text(cmd, encoding="utf-8")
    print(f"[*] 已提交: {cmd}")
    if not wait:
        return 0
    print("[*] 等待执行器……（如果一直没反应，说明执行器没在跑）")
    deadline = time.time() + 900
    while time.time() < deadline:
        if DONE.exists():
            time.sleep(0.3)
            print("[*] ---- 输出开始 ----")
            try:
                print(OUT.read_text(encoding="utf-8", errors="replace"))
            except Exception as e:  # noqa: BLE001
                print(f"[!] 读不到输出: {e}")
            print("[*] ---- 输出结束 ----")
            return 0
        time.sleep(0.4)
    print("[X] 超时等不到完成标记")
    return 4


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--submit", metavar="CMD", help="提交一条作业并等待结果")
    ap.add_argument("--no-wait", action="store_true", help="提交后不等结果")
    ap.add_argument("--stop", action="store_true", help="让执行器退出")
    ap.add_argument("--batch", metavar="FILE",
                    help="批处理：一次提权连着跑文件里的多条命令，"
                         "每条输出写 server/hook_runs/_batch_<i>.out")
    ap.add_argument("--watch", action="store_true", help="常驻待命（默认行为）")
    ap.add_argument("--timeout", type=float, default=900.0,
                    help="单条作业最长运行秒数（默认 900）；长驻实验用 --timeout 7200")
    ap.add_argument("--done-marker", default=None,
                    help="批处理跑完时写这个文件（默认 server/hook_runs/_batch.done）")
    args = ap.parse_args()

    global JOB_TIMEOUT, DONE_MARKER
    JOB_TIMEOUT = max(10.0, float(args.timeout))
    DONE_MARKER = Path(args.done_marker) if args.done_marker else JOBDIR / "_batch.done"

    if args.batch:
        JOBDIR.mkdir(parents=True, exist_ok=True)
        if not is_admin():
            # 每轮用**唯一**的完成标记：共享的 _batch.done 会被上一轮执行器
            # 在收尾时写掉，导致本轮的包装进程立刻误判"已完成"而退出，整棵
            # 提权进程树随之被回收（2026-10-14 20:17 实测踩坑）。
            marker = JOBDIR / f"_batch.done.{os.getpid()}"
            try:
                if marker.exists():
                    marker.unlink()
            except Exception:  # noqa: BLE001
                pass
            elevate_self(["--batch", str(Path(args.batch).resolve()),
                          "--timeout", str(JOB_TIMEOUT),
                          "--done-marker", str(marker)], wait=False,
                         exit_after=False)
            # 关键：父进程必须一直活着，否则同一作业对象里的提权子进程会被回收。
            deadline = time.time() + JOB_TIMEOUT + 600.0
            print(f"[*] 等待提权子进程跑完（保持本窗口打开）；完成标记={marker.name}",
                  flush=True)
            while time.time() < deadline and not marker.exists():
                time.sleep(1.0)
            print("[*] 结束等待。", flush=True)
            return 0
        return run_batch(Path(args.batch))
    if args.stop:
        JOBDIR.mkdir(parents=True, exist_ok=True)
        STOP.write_text("stop", encoding="utf-8")
        print("[*] 已写入 _job.stop")
        return 0
    if args.submit:
        return submit(args.submit, not args.no_wait)
    elevate_self(["--watch", "--timeout", str(JOB_TIMEOUT)], wait=True)
    return watch()


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as e:  # noqa: BLE001
        import traceback
        wlog("顶层异常: " + traceback.format_exc())
        raise
