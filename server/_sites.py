"""Show the branch immediately before each 49235 and 49236 report."""

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

import capstone

EXE = list(Path(r"D:\project\gundam-reburn\launcher\gundam").rglob("GundamOnline_CHINA.exe"))[0]
OUT = Path(r"D:\project\gundam-reburn\server\os_sites.txt")
PATTERNS = {
    "49236": bytes.fromhex("c744241454c00000"),
    "49235": bytes.fromhex("c744241453c00000"),
}
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
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    lines = []
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    while addr < 0x80000000 and len(lines) < 400:
        if k32.VirtualQueryEx(ph, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        size = int(mbi.RegionSize)
        base = int(mbi.BaseAddress or 0)
        if int(mbi.State) == 0x1000 and int(mbi.Protect) & 0xF0 and 0 < size <= 8 * 1024 * 1024:
            blob = readmem(ph, base, size)
            for name, pat in PATTERNS.items():
                start = 0
                n = 0
                while n < 6:
                    i = blob.find(pat, start)
                    if i < 0:
                        break
                    at = base + i
                    lines.append(f"--- {name} {at:#x} ---")
                    window = blob[max(0, i - 0x40) : i + 0x18]
                    origin = at - (i - max(0, i - 0x40))
                    for insn in md.disasm(window, origin):
                        mark = " <" if insn.address == at else ""
                        lines.append(f"{insn.address:#x} {insn.bytes.hex():20} {insn.mnemonic} {insn.op_str}{mark}")
                    n += 1
                    start = i + len(pat)
        addr = base + max(size, 1)
    k32.CloseHandle(ph)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("lines", len(lines))


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
