"""纯净启动客户端：不注入 frida、不打任何 hook，只观察它自己会怎样。

用途：把"某个现象是环境造成的"和"是 frida 注入造成的"分开。
保护模块的那些弹窗（内部错误码 49234/49235/49236）和 Themida 壳的
反虚拟机弹窗（"Sorry, this application cannot run under a Virtual Machine"）
都发生在没有 frida 的情况下——本工具用来证明这一点。

用法：
    python tools/plain_launch.py                 # 启动并观察 30 秒
    python tools/plain_launch.py --seconds 60
    python tools/plain_launch.py --kill          # 观察完杀掉（默认不杀，方便你亲眼看看）
    python tools/plain_launch.py --elevate       # 用 UAC 提权启动（会弹确认框）

注意：保护模块要 CreateService/StartService 一个内核驱动，**必须提权**。
      非提权时会得到「内部错误码 49235 / 错误信息码 0x5」，那是 ACCESS_DENIED，
      不是"防火墙没放行"（弹窗文案是张冠李戴的）。
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ARG = "./data/"

# 保护模块会落盘的驱动，用来判断"驱动到底装没装上去"
CPS_PATHS = [
    r"C:\Windows\SysWOW64\CPS.sys",
    r"C:\Windows\System32\CPS.sys",
    r"C:\Windows\SysWOW64\drivers\CPS.sys",
    r"C:\Windows\System32\drivers\CPS.sys",
]


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.DWORD),
        ("fMask", ctypes.c_ulong),
        ("hwnd", wt.HWND),
        ("lpVerb", wt.LPCWSTR),
        ("lpFile", wt.LPCWSTR),
        ("lpParameters", wt.LPCWSTR),
        ("lpDirectory", wt.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wt.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wt.LPCWSTR),
        ("hkeyClass", wt.HKEY),
        ("dwHotKey", wt.DWORD),
        ("hIcon", wt.HANDLE),
        ("hProcess", wt.HANDLE),
    ]


SEE_MASK_NOCLOSEPROCESS = 0x00000040
SEE_MASK_NOASYNC = 0x00000100
SW_SHOWNORMAL = 1


def launch_elevated(exe: Path, arg: str) -> int:
    """用 runas 提权启动，返回 pid。会弹 UAC 确认框。"""
    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
    sei.lpVerb = "runas"
    sei.lpFile = str(exe)
    sei.lpParameters = arg
    sei.lpDirectory = str(exe.parent)
    sei.nShow = SW_SHOWNORMAL
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        err = ctypes.get_last_error() or ctypes.windll.kernel32.GetLastError()
        raise OSError(f"ShellExecuteExW(runas) 失败，错误码 {err}"
                      f"（1223 = 用户取消了 UAC）")
    h = sei.hProcess
    pid = ctypes.windll.kernel32.GetProcessId(h)
    return int(pid), h


def wait_elevated(h, timeout: float) -> int | None:
    """等待提权进程结束；返回退出码或 None（超时）。"""
    k32 = ctypes.windll.kernel32
    rc = k32.WaitForSingleObject(h, int(timeout * 1000))
    if rc == 0x00000102:  # WAIT_TIMEOUT
        return None
    code = ctypes.c_ulong()
    k32.GetExitCodeProcess(h, ctypes.byref(code))
    return int(code.value)


def find_exe() -> Path:
    found = [p for p in (ROOT / "launcher").rglob("GundamOnline_CHINA.exe")
             if p.parent.name == "GundamOnline"]
    if not found:
        raise SystemExit("找不到 GundamOnline_CHINA.exe")
    return found[0]


def collect_window_texts(pid: int) -> list[str]:
    """抓目标进程所有顶层窗口 + 子控件的文字。"""
    user32 = ctypes.windll.user32
    found: list[str] = []

    def read_text(hwnd: int) -> str:
        buf = ctypes.create_unicode_buffer(2000)
        res = ctypes.c_size_t()
        ok = user32.SendMessageTimeoutW(hwnd, 0x000D, 2000, buf, 0x0002, 80, ctypes.byref(res))
        return buf.value.strip() if ok else ""

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def on_child(hwnd, _lp):
        t = read_text(hwnd)
        if t:
            found.append(t)
        return True

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def on_top(hwnd, _lp):
        proc = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(proc))
        if proc.value != pid:
            return True
        t = read_text(hwnd)
        if t:
            found.append(t)
        user32.EnumChildWindows(hwnd, on_child, 0)
        return True

    user32.EnumWindows(on_top, 0)
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seconds", type=float, default=30.0)
    ap.add_argument("--arg", dest="game_args", default=DEFAULT_ARG)
    ap.add_argument("--kill", action="store_true")
    ap.add_argument("--elevate", action="store_true",
                    help="用 UAC 提权启动（保护模块必须提权才能 CreateService）")
    args = ap.parse_args()

    if sys.platform != "win32":
        print("仅 Windows。", file=sys.stderr)
        return 2

    exe = find_exe()
    print(f"[*] 启动: {exe}")
    print(f"[*] 参数: {args.game_args!r}   cwd: {exe.parent}")
    print(f"[*] 提权: {'是（会弹 UAC 确认框，请点“是”）' if args.elevate else '否（可能因权限不足失败）'}")

    seen: list[str] = []
    hproc = None
    proc = None

    if args.elevate:
        try:
            pid, hproc = launch_elevated(exe, args.game_args)
        except OSError as e:
            print(f"[X] {e}")
            return 3
        print(f"[*] pid = {pid}   （无 frida、无 hook，已提权）\n")
    else:
        proc = subprocess.Popen([str(exe), args.game_args], cwd=str(exe.parent))
        pid = proc.pid
        print(f"[*] pid = {pid}   （无 frida、无 hook）\n")

    cps_seen: list[str] = []
    deadline = time.monotonic() + args.seconds
    exited: int | None = None
    while time.monotonic() < deadline:
        # 驱动是否落盘
        for p in CPS_PATHS:
            if p not in cps_seen and Path(p).exists():
                cps_seen.append(p)
                print(f"[驱动] 出现: {p}  ({Path(p).stat().st_size} 字节)")
        # 进程是否已退
        if args.elevate:
            code = wait_elevated(hproc, 0.0)
            if code is not None:
                exited = code
                print(f"\n[=] 进程已退出，退出码 = {code}")
                break
        else:
            if proc.poll() is not None:
                exited = proc.returncode
                print(f"\n[=] 进程已退出，退出码 = {proc.returncode}")
                break
        # 窗口文字（目标若为高完整性进程，UIPI 可能挡住，读不到属正常）
        for t in collect_window_texts(pid):
            if t not in seen:
                seen.append(t)
                print(f"[窗口] {t}")
        time.sleep(0.4)
    else:
        print(f"\n[=] 观察时间到（{args.seconds:.0f}s），进程仍在运行 (pid={pid})")

    if args.kill:
        if args.elevate and exited is None:
            ctypes.windll.kernel32.TerminateProcess(hproc, 0)
            print("[=] 已结束进程")
        elif proc is not None and proc.poll() is None:
            proc.kill()
            print("[=] 已结束进程")

    print("\n[=] 驱动落盘情况:", cps_seen or "（没有出现）")
    if seen:
        print("[=] 捕获到的窗口文字:")
        for t in seen:
            print("     ", t.replace("\n", " | "))
    else:
        print("[=] 没有捕获到任何窗口文字")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    raise SystemExit(main())
