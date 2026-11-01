"""Dump the decrypted error-message templates and the code that points at them."""

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

EXE = list(Path(r"D:\project\gundam-reburn\launcher\gundam").rglob("GundamOnline_CHINA.exe"))[0]
OUT = Path(r"D:\project\gundam-reburn\server\os_tmpl.txt")
k32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
NEEDLE = "内部错误码".encode("utf-16le")
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
EXEC = 0x20 | 0x40 | 0x80


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


def regions(handle):
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    while addr < 0x80000000:
        if k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        size = int(mbi.RegionSize)
        base = int(mbi.BaseAddress or 0)
        yield base, size, int(mbi.State), int(mbi.Protect)
        addr = base + max(size, 1)


def read(handle, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)):
        return b""
    return buf.raw[: got.value]


def u16_runs(data, base):
    lines = []
    i = 0
    while i + 4 < len(data):
        chars = []
        j = i
        while j + 1 < len(data):
            lo, hi = data[j], data[j + 1]
            if lo == 0 and hi == 0:
                break
            cp = lo | (hi << 8)
            if cp < 32 or cp >= 0xD800:
                break
            chars.append(chr(cp))
            j += 2
            if len(chars) > 180:
                break
        if len(chars) >= 8:
            lines.append(f"{base + i:#x} {''.join(chars)}")
            i = j + 2
        else:
            i += 2
    return lines


def main() -> None:
    proc = subprocess.Popen([str(EXE), "./data/"], cwd=str(EXE.parent))
    for _ in range(30):
        time.sleep(0.3)
        if titled(proc.pid):
            break
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, proc.pid)
    lines = [f"pid {proc.pid}"]
    hits = []
    chunks = []
    for base, size, state, prot in regions(handle):
        if state != MEM_COMMIT or prot & PAGE_NOACCESS or prot & PAGE_GUARD or size > 16 * 1024 * 1024 or size <= 0:
            continue
        data = read(handle, base, size)
        if not data:
            continue
        chunks.append((base, prot, data))
        start = 0
        while True:
            i = data.find(NEEDLE, start)
            if i < 0:
                break
            hits.append(base + i)
            start = i + 2
    lines.append("hits " + " ".join(hex(h) for h in hits))
    for hit in hits:
        if hit < 0x100000:
            continue
        for base, prot, data in chunks:
            if base <= hit < base + len(data):
                rel = hit - base
                window = data[max(0, rel - 0x800) : rel + 0x400]
                lines.append(f"--- around {hit:#x} prot {prot:#x} ---")
                lines.extend(u16_runs(window, base + max(0, rel - 0x800)))
                break
    targets = [h for h in hits if h >= 0x100000]
    ptr_needles = [h.to_bytes(4, "little") for h in targets]
    for base, prot, data in chunks:
        if not (prot & EXEC):
            continue
        for target, needle in zip(targets, ptr_needles):
            start = 0
            n = 0
            while n < 4:
                i = data.find(needle, start)
                if i < 0:
                    break
                lines.append(f"xref {base + i:#x} -> {target:#x} prot {prot:#x}")
                n += 1
                start = i + 4
    k32.CloseHandle(handle)
    OUT.write_text("\n".join(lines), encoding="utf-8", errors="replace")
    print("lines", len(lines), "hits", len(hits))


def titled(pid):
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def on_top(hwnd, _lp):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid:
            buf = ctypes.create_unicode_buffer(80)
            user32.GetWindowTextW(hwnd, buf, 80)
            if "发现错误" in buf.value:
                found.append(1)
        return True

    user32.EnumWindows(on_top, 0)
    return bool(found)


if __name__ == "__main__":
    main()
