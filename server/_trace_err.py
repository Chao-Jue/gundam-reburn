"""Capture the live error dialog and locate its message template in memory."""

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

EXE = list(Path(r"D:\project\gundam-reburn\launcher\gundam").rglob("GundamOnline_CHINA.exe"))[0]
OUT = Path(r"D:\project\gundam-reburn\server\os_trace.txt")
k32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E

NEEDLES = {
    "gbk-os": "暂不支持您的操作系统".encode("gbk"),
    "gbk-inner": "内部错误码".encode("gbk"),
    "u16-inner": "内部错误码".encode("utf-16le"),
    "u16-os": "操作系统".encode("utf-16le"),
    "code": (49236).to_bytes(4, "little"),
}


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def main() -> None:
    proc = subprocess.Popen([str(EXE), "./data/"], cwd=str(EXE.parent))
    hwnds: list[int] = []
    for _ in range(30):
        time.sleep(0.3)
        hwnds = windows(proc.pid)
        if any("发现错误" in text for _, text in hwnds):
            break
    lines = [f"pid {proc.pid}"]
    for hwnd, text in hwnds:
        lines.append(f"win {hwnd:#x} {text}")
        lines.extend(child_text(hwnd))
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, proc.pid)
    if not handle:
        lines.append(f"open fail {k32.GetLastError()}")
        OUT.write_text("\n".join(lines), encoding="utf-8")
        return
    found = {name: [] for name in NEEDLES}
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    while addr < 0x80000000:
        if k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        size = int(mbi.RegionSize)
        base = int(mbi.BaseAddress or 0)
        prot = int(mbi.Protect)
        if mbi.State == MEM_COMMIT and not (prot & PAGE_NOACCESS) and not (prot & PAGE_GUARD) and 0 < size <= 16 * 1024 * 1024:
            buf = ctypes.create_string_buffer(size)
            got = ctypes.c_size_t()
            if k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(got)):
                data = buf.raw[: got.value]
                for name, needle in NEEDLES.items():
                    if len(found[name]) >= 8:
                        continue
                    start = 0
                    while len(found[name]) < 8:
                        i = data.find(needle, start)
                        if i < 0:
                            break
                        at = base + i
                        if name != "code" or 0x400000 <= at < 0x1300000:
                            found[name].append(at)
                        start = i + len(needle)
        addr = base + max(size, 1)
    k32.CloseHandle(handle)
    for name, hits in found.items():
        lines.append(f"{name} {', '.join(hex(h) for h in hits) or 'none'}")
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("wrote", len(lines))


def windows(pid: int) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def on_top(hwnd, _lp):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid:
            buf = ctypes.create_unicode_buffer(400)
            user32.GetWindowTextW(hwnd, buf, 400)
            found.append((int(hwnd), buf.value))
        return True

    user32.EnumWindows(on_top, 0)
    return found


def child_text(parent: int) -> list[str]:
    lines: list[str] = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def on_child(hwnd, _lp):
        buf = ctypes.create_unicode_buffer(800)
        user32.SendMessageW(hwnd, WM_GETTEXT, 800, buf)
        if buf.value:
            lines.append(f"  child {int(hwnd):#x} {buf.value[:300]}")
        return True

    user32.EnumChildWindows(parent, on_child, 0)
    return lines


if __name__ == "__main__":
    main()
