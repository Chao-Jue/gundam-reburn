"""Launch the game and write the decrypted dialog strings plus owning module."""

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

EXE = list(Path(r"D:\project\gundam-reburn\launcher\gundam").rglob("GundamOnline_CHINA.exe"))[0]
OUT = Path(r"D:\project\gundam-reburn\server\os_strings.txt")
k32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
psapi = ctypes.windll.psapi

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100


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


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", ctypes.c_void_p),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]


def titles(pid: int) -> list[str]:
    found: list[str] = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def on_top(hwnd, _lp):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid:
            buf = ctypes.create_unicode_buffer(200)
            user32.GetWindowTextW(hwnd, buf, 200)
            if buf.value:
                found.append(buf.value)
        return True

    user32.EnumWindows(on_top, 0)
    return found


def read(handle, addr, size) -> bytes:
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)):
        return b""
    return buf.raw[: got.value]


def u16_strings(data: bytes, base: int) -> list[str]:
    lines = []
    i = 0
    while i + 8 < len(data):
        if data[i + 1] == 0 and 0x20 <= data[i] < 0x7F:
            j = i
            chars = []
            while j + 1 < len(data) and data[j + 1] == 0 and data[j] != 0:
                chars.append(chr(data[j]))
                j += 2
            if len(chars) >= 6:
                lines.append(f"{base + i:#x} {''.join(chars)[:160]}")
            i = j + 2
        else:
            i += 2
    return lines


def main() -> None:
    proc = subprocess.Popen([str(EXE), "./data/"], cwd=str(EXE.parent))
    for _ in range(25):
        time.sleep(0.3)
        if any("发现错误" in t for t in titles(proc.pid)):
            break
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, proc.pid)
    lines = [f"pid {proc.pid}"]
    snap = k32.CreateToolhelp32Snapshot(0x18, proc.pid)
    entry = MODULEENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    ok = k32.Module32FirstW(snap, ctypes.byref(entry))
    while ok:
        start = int(entry.modBaseAddr or 0)
        lines.append(f"mod {entry.szModule} {start:#x}+{entry.modBaseSize:#x}")
        if start <= 0x1AFBA8 < start + int(entry.modBaseSize):
            lines.append(f"OWNER {entry.szModule}")
        ok = k32.Module32NextW(snap, ctypes.byref(entry))
    k32.CloseHandle(snap)
    region = read(handle, 0x1AF000, 0x2000)
    lines.append("---ascii---")
    lines.extend(u16_strings(region, 0x1AF000))
    lines.append("---cjk---")
    text = region.decode("utf-16le", errors="replace")
    buf = []
    start = None
    for idx, ch in enumerate(text):
        if "\u4e00" <= ch <= "\u9fff":
            if start is None:
                start = idx
            buf.append(ch)
        elif buf:
            if len(buf) >= 4:
                lines.append(f"{0x1AF000 + start * 2:#x} {''.join(buf)[:200]}")
            buf = []
            start = None
    k32.CloseHandle(handle)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("wrote", OUT, "lines", len(lines))


if __name__ == "__main__":
    main()
