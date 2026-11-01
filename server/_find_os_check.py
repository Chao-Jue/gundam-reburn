"""Launch the game, then locate the code that creates the OS error dialog."""

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

EXE = list(Path(r"D:\project\gundam-reburn\launcher\gundam").rglob("GundamOnline_CHINA.exe"))[0]
NEEDLE = "发现错误".encode("utf-16le")
k32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

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


def launch() -> int:
    proc = subprocess.Popen([str(EXE), "./data/"], cwd=str(EXE.parent))
    for _ in range(20):
        time.sleep(0.4)
        titles = window_titles(proc.pid)
        if any("发现错误" in title for title in titles):
            return proc.pid
    return proc.pid


def window_titles(pid: int) -> list[str]:
    titles: list[str] = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def on_top(hwnd, _lp):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value != pid:
            return True
        buf = ctypes.create_unicode_buffer(200)
        user32.GetWindowTextW(hwnd, buf, 200)
        if buf.value:
            titles.append(buf.value)
        return True

    user32.EnumWindows(on_top, 0)
    return titles


def scan(pid: int) -> list[int]:
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise SystemExit(f"OpenProcess failed {k32.GetLastError()}")
    hits: list[int] = []
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    while addr < 0x80000000:
        if k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        size = int(mbi.RegionSize)
        base = int(mbi.BaseAddress or 0)
        prot = int(mbi.Protect)
        if mbi.State == MEM_COMMIT and not (prot & PAGE_NOACCESS) and not (prot & PAGE_GUARD) and 0 < size <= 32 * 1024 * 1024:
            buf = ctypes.create_string_buffer(size)
            read = ctypes.c_size_t()
            if k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(read)):
                data = buf.raw[: read.value]
                start = 0
                while True:
                    i = data.find(NEEDLE, start)
                    if i < 0:
                        break
                    hits.append(base + i)
                    start = i + 2
        addr = base + max(size, 1)
    k32.CloseHandle(handle)
    return hits


def main() -> None:
    pid = launch()
    print("pid", pid, "titles", window_titles(pid))
    hits = scan(pid)
    print("hits", [hex(h) for h in hits[:20]], "count", len(hits))
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    blob = ctypes.create_string_buffer(0x3000)
    got = ctypes.c_size_t()
    k32.ReadProcessMemory(handle, ctypes.c_void_p(0x1AE000), blob, 0x3000, ctypes.byref(got))
    raw = blob.raw[: got.value]
    text = raw.decode("utf-16le", errors="replace").replace("\x00", "\n")
    out = Path(r"D:\project\gundam-reburn\server\os_dump.txt")
    out.write_text(text, encoding="utf-8")
    print("dump", got.value, "chars", len(text))
    needles = [h.to_bytes(4, "little") for h in hits]
    ptrs: list[tuple[int, int]] = []
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    while addr < 0x80000000 and len(ptrs) < 30:
        if k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        size = int(mbi.RegionSize)
        base = int(mbi.BaseAddress or 0)
        prot = int(mbi.Protect)
        if mbi.State == MEM_COMMIT and not (prot & PAGE_NOACCESS) and not (prot & PAGE_GUARD) and 0 < size <= 8 * 1024 * 1024:
            raw = ctypes.create_string_buffer(size)
            got = ctypes.c_size_t()
            if k32.ReadProcessMemory(handle, ctypes.c_void_p(base), raw, size, ctypes.byref(got)):
                data = raw.raw[: got.value]
                for hit, needle in zip(hits, needles):
                    start = 0
                    while len(ptrs) < 30:
                        i = data.find(needle, start)
                        if i < 0:
                            break
                        ptrs.append((base + i, hit))
                        start = i + 4
        addr = base + max(size, 1)
    k32.CloseHandle(handle)
    for where, target in ptrs:
        print(f"PTR {where:#x} -> {target:#x}")


if __name__ == "__main__":
    main()
