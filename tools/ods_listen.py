# -*- coding: utf-8 -*-
"""ods_listen.py —— 进程外旁听 OutputDebugString（DBWIN_BUFFER 协议）。

⚠️ 本工具对目标进程**零接触**：
   - 不 OpenProcess 写内存 / 不 WriteProcessMemory / 不 CreateRemoteThread
   - 不改一行代码字节、不改一个 vtable 槽、不 attach 成调试器
   - 只是在自己进程里映射系统建的共享内存 `DBWIN_BUFFER`，并收发两个命名事件

   所以 CPS 的代码自检（`0x70E9`，比的是**自己进程内**的代码字节）看不到任何东西。

用法：
   python tools/ods_listen.py --check                     # 只检查有没有别的监听者
   python tools/ods_listen.py                             # 收全机器所有进程的 ODS
   python tools/ods_listen.py --pid 1234                  # 只收某进程
   python tools/ods_listen.py --pid-name GundamOnline_CHINA.exe --exit-with-process
   python tools/ods_listen.py --grep recv_pilot --file server/ods.log

集成到 start_local.cmd 时的推荐组合（cmd 里已经这么写了）：
   --pid-name GundamOnline_CHINA.exe --exit-with-process --wait-process-timeout 300
   --file server/ods_live.log

安全设计（避免拖住被观察的程序）：
   1. 读到缓冲后**立刻** SetEvent(DBWIN_BUFFER_READY)，再做筛选/打印；
   2. 打印在独立线程里做，主循环永不做 IO；
   3. WaitForSingleObject 用 500ms 超时，Ctrl-C 随时能退；
   4. 退出后事件句柄关闭，被观察方下次 ODS 调用自动退化为"没人听"，不阻塞；
   5. `--max-mb` 到量自动停，避免游戏刷日志把盘写满。

⚠️ DBWIN 是"抢"的机制：**同一时刻只能有一个监听者**。
   本机会话里如果已有 DebugView / VS 输出窗口 / 另一个本工具的实例，
   双方会互抢 BUFFER_READY，可能让写入方卡在 OutputDebugString（卡顿，不崩）。
   所以启动时会探测 `DBWIN_BUFFER` 是否已被别人创建，默认拒绝启动（`--force` 可强上）。

注意：所有 stdout 输出刻意用 ASCII —— 这个脚本会被 .cmd 以 GBK 控制台启动，
中文会变乱码。
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import queue
import struct
import sys
import threading
import time
from datetime import datetime

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PAGE_READWRITE = 0x04
FILE_MAP_READ = 0x0004
WAIT_OBJECT_0 = 0x00000000
ERROR_ALREADY_EXISTS = 183
BUFFER_SIZE = 4096
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

k32.CreateEventW.restype = wt.HANDLE
k32.CreateEventW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR]
k32.CreateFileMappingW.restype = wt.HANDLE
k32.CreateFileMappingW.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                                   wt.DWORD, wt.DWORD, wt.LPCWSTR]
k32.MapViewOfFile.restype = ctypes.c_void_p
k32.MapViewOfFile.argtypes = [wt.HANDLE, wt.DWORD, wt.DWORD, wt.DWORD, ctypes.c_size_t]
k32.UnmapViewOfFile.restype = wt.BOOL
k32.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
k32.SetEvent.restype = wt.BOOL
k32.SetEvent.argtypes = [wt.HANDLE]
k32.WaitForSingleObject.restype = wt.DWORD
k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
k32.CloseHandle.restype = wt.BOOL
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]


# ---------------------------------------------------------------- 进程查询

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


def find_pid_by_name(name: str) -> int:
    """按 exe 名找 pid（不区分大小写）。找不到返回 0。"""
    TH32CS_SNAPPROCESS = 0x00000002
    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    k32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (0, INVALID_HANDLE_VALUE):
        return 0
    try:
        e = PROCESSENTRY32W()
        e.dwSize = ctypes.sizeof(e)
        if not k32.Process32FirstW(snap, ctypes.byref(e)):
            return 0
        while True:
            if e.szExeFile.lower() == name.lower():
                return int(e.th32ProcessID)
            if not k32.Process32NextW(snap, ctypes.byref(e)):
                return 0
    finally:
        k32.CloseHandle(snap)


def pid_alive(pid: int) -> bool:
    h = k32.OpenProcess(0x1000, False, pid)      # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return False
    k32.CloseHandle(h)
    return True


def probe_foreign_listener() -> bool:
    """`DBWIN_BUFFER` 已存在 ⇒ 别的监听者先在听了。"""
    h = k32.CreateFileMappingW(wt.HANDLE(-1), None, PAGE_READWRITE, 0, BUFFER_SIZE,
                               "DBWIN_BUFFER")
    if not h:
        return False
    existed = ctypes.get_last_error() == ERROR_ALREADY_EXISTS
    k32.CloseHandle(h)
    return existed


# ---------------------------------------------------------------- 监听主体

class OdsListener:
    def __init__(self) -> None:
        ctypes.set_last_error(0)
        self.h_map = k32.CreateFileMappingW(
            wt.HANDLE(-1), None, PAGE_READWRITE, 0, BUFFER_SIZE, "DBWIN_BUFFER")
        if not self.h_map:
            _err("CreateFileMappingW(DBWIN_BUFFER)")
        self.addr = k32.MapViewOfFile(self.h_map, FILE_MAP_READ, 0, 0, BUFFER_SIZE)
        if not self.addr:
            _err("MapViewOfFile")

        self.h_data = k32.CreateEventW(None, False, False, "DBWIN_DATA_READY")
        if not self.h_data:
            _err("CreateEventW(DBWIN_DATA_READY)")
        self.h_ready = k32.CreateEventW(None, False, True, "DBWIN_BUFFER_READY")
        if not self.h_ready:
            _err("CreateEventW(DBWIN_BUFFER_READY)")

    def read_one(self, timeout_ms: int = 500):
        """返 (pid, text) 或 None。返回前已经把 BUFFER_READY 交还，尽量缩短占用窗口。"""
        rc = k32.WaitForSingleObject(self.h_data, timeout_ms)
        if rc != WAIT_OBJECT_0:
            return None
        pid = struct.unpack_from("<I", ctypes.string_at(self.addr, 4))[0]
        raw = ctypes.string_at(self.addr + 4)          # NUL 结尾
        k32.SetEvent(self.h_ready)                     # ★ 立刻交还，后面才是慢活
        return pid, raw.decode("mbcs", "replace")

    def close(self) -> None:
        for h in (self.h_ready, self.h_data):
            if h:
                k32.CloseHandle(h)
        if self.addr:
            k32.UnmapViewOfFile(self.addr)
        if self.h_map:
            k32.CloseHandle(self.h_map)


def _err(where: str) -> None:
    e = ctypes.get_last_error()
    raise OSError(f"{where} 失败 (WinError {e}): {ctypes.FormatError(e)}")


def _printer(q: "queue.Queue[str | None]", fh, echo: bool) -> None:
    while True:
        line = q.get()
        if line is None:
            break
        try:
            fh.write(line + "\n")
            fh.flush()
        except Exception:      # noqa: BLE001
            pass
        if echo:
            try:
                print(line, flush=True)
            except Exception:  # noqa: BLE001
                pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="zero-injection OutputDebugString listener")
    ap.add_argument("--pid", type=int, default=0, help="only this pid (0 = all)")
    ap.add_argument("--pid-name", default="",
                    help="only this exe name (waits for it to appear)")
    ap.add_argument("--exit-with-process", action="store_true",
                    help="quit when the watched process exits")
    ap.add_argument("--wait-process-timeout", type=float, default=0,
                    help="give up after N seconds waiting for --pid-name (0 = forever)")
    ap.add_argument("--grep", default="", help="only lines containing this substring")
    ap.add_argument("--file", default="", help="append to this file")
    ap.add_argument("--seconds", type=float, default=0, help="auto-exit after N seconds")
    ap.add_argument("--max-mb", type=float, default=64.0, help="stop after N MB of log")
    ap.add_argument("--quiet", action="store_true", help="no stdout, file only")
    ap.add_argument("--force", action="store_true",
                    help="start even if another listener is attached")
    ap.add_argument("--check", action="store_true",
                    help="only report whether another listener exists")
    args = ap.parse_args(argv)

    if args.check:
        if probe_foreign_listener():
            print("[WARN] DBWIN_BUFFER already exists - another listener is attached "
                  "(DebugView / VS Output / a previous instance of this tool).",
                  flush=True)
            return 3
        print("[ok] no other ODS listener", flush=True)
        return 0

    if probe_foreign_listener() and not args.force:
        print("[!] another ODS listener is already attached (DBWIN_BUFFER exists).",
              flush=True)
        print("    two listeners fight over BUFFER_READY and may stall the game "
              "inside OutputDebugString.", flush=True)
        print("    close DebugView / VS Output / the previous instance first, "
              "or pass --force.", flush=True)
        return 3

    lis = OdsListener()
    q: "queue.Queue[str | None]" = queue.Queue(maxsize=20000)
    if args.file:
        os.makedirs(os.path.dirname(os.path.abspath(args.file)) or ".", exist_ok=True)
        fh = open(args.file, "a", encoding="utf-8", buffering=1)
    else:
        fh = sys.stdout
    th = threading.Thread(target=_printer,
                          args=(q, fh, (not args.quiet) and (fh is not sys.stdout)),
                          daemon=True)
    th.start()

    target = args.pid
    tip = "[*] listening "
    tip += (f"pid={target} " if target else
            (f"waiting for {args.pid_name} " if args.pid_name else "pid=ALL "))
    if args.grep:
        tip += f"grep={args.grep!r} "
    if args.file:
        tip += f"-> {args.file}"
    print(tip, flush=True)

    grep = args.grep.lower()
    n_raw = n_hit = 0
    bytes_out = 0
    limit = int(args.max_mb * 1024 * 1024)
    t_end = time.time() + args.seconds if args.seconds > 0 else None
    t_name_poll = 0.0
    t_wait = (time.time() + args.wait_process_timeout
              if args.pid_name and args.wait_process_timeout > 0 else None)
    try:
        while True:
            if t_end and time.time() >= t_end:
                print("[*] time limit reached, exiting", flush=True)
                break
            if t_wait and not target and time.time() >= t_wait:
                print(f"[*] waited {args.wait_process_timeout:.0f}s for "
                      f"{args.pid_name}, giving up", flush=True)
                break

            # 惰性解析 --pid-name（游戏比监听器起得晚）
            if args.pid_name and not target:
                if time.time() >= t_name_poll:
                    t_name_poll = time.time() + 1.0
                    found = find_pid_by_name(args.pid_name)
                    if found:
                        target = found
                        print(f"[*] attached {args.pid_name} pid={target}", flush=True)
            if args.exit_with_process and target and not pid_alive(target):
                print(f"[*] watched process {target} exited, stopping", flush=True)
                break

            got = lis.read_one(500)
            if got is None:
                continue
            pid, text = got
            n_raw += 1
            if target and pid != target:
                continue
            if args.pid_name and not target:
                continue          # 还没等到目标进程：别把全机器的日志灌进文件
            if grep and grep not in text.lower():
                continue
            n_hit += 1
            text = text.rstrip("\r\n")
            line = f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]} [{pid:>5}] {text}"
            bytes_out += len(line) + 1
            try:
                q.put_nowait(line)
            except queue.Full:
                pass
            if limit and bytes_out >= limit:
                print(f"[*] reached --max-mb {args.max_mb}, stopping", flush=True)
                break
    except KeyboardInterrupt:
        print("\n[*] Ctrl-C", flush=True)
    finally:
        time.sleep(0.2)
        try:
            q.put_nowait(None)
        except queue.Full:
            pass
        th.join(timeout=2.0)
        lis.close()
        if fh is not sys.stdout:
            fh.close()
        print(f"[*] done: {n_raw} ODS lines seen, {n_hit} matched", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
