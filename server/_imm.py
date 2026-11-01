"""Classify every instruction that materializes error 49235 or 49236."""

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

EXE = list(Path(r"D:\project\gundam-reburn\launcher\gundam").rglob("GundamOnline_CHINA.exe"))[0]
OUT = Path(r"D:\project\gundam-reburn\server\os_imm.txt")
k32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32


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


def readmem(handle, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
    return buf.raw[: got.value]


def main() -> None:
    proc = subprocess.Popen([str(EXE), "./data/"], cwd=str(EXE.parent))
    for _ in range(40):
        time.sleep(0.25)
        if dialog(proc.pid):
            break
    ph = k32.OpenProcess(0x0410, False, proc.pid)
    lines = []
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    needles = {b"\x53\xc0\x00\x00": "49235", b"\x54\xc0\x00\x00": "49236"}
    while addr < 0x80000000:
        if k32.VirtualQueryEx(ph, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        size = int(mbi.RegionSize)
        base = int(mbi.BaseAddress or 0)
        if int(mbi.State) == 0x1000 and int(mbi.Protect) & 0xF0 and 0 < size <= 8 * 1024 * 1024:
            blob = readmem(ph, base, size)
            for needle, name in needles.items():
                start = 0
                while True:
                    i = blob.find(needle, start)
                    if i < 0 or i < 3:
                        break
                    prev = blob[i - 3 : i]
                    # skip the dialog's mov [esp+14], imm which is c7 44 24 14
                    if prev != bytes.fromhex("442414"):
                        lines.append(f"{name} {base + i:#x} prev {prev.hex()}")
                    start = i + 1
                    if len(lines) > 80:
                        break
        addr = base + max(size, 1)
    k32.CloseHandle(ph)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("hits", len(lines))


def dialog(pid):
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def on_top(hwnd, _lp):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid:
            buf = ctypes.create_unicode_buffer(40)
            user32.GetWindowTextW(hwnd, buf, 40)
            if "发现错误" in buf.value:
                found.append(1)
                return False
        return True

    user32.EnumWindows(on_top, 0)
    return bool(found)


if __name__ == "__main__":
    main()
