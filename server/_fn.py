"""Disassemble the function that reports error 49235, from its prologue."""

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

import capstone

EXE = list(Path(r"D:\project\gundam-reburn\launcher\gundam").rglob("GundamOnline_CHINA.exe"))[0]
OUT = Path(r"D:\project\gundam-reburn\server\os_fn.txt")
MARK = bytes.fromhex("c784243008000012000000")
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
    at, blob, base = find_mark(ph)
    rel = at - base
    before = blob[max(0, rel - 0x3000) : rel]
    pad = before.rfind(b"\xcc\xcc\xcc")
    start = at - (len(before) - pad - 3) if pad >= 0 else at - 0x200
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    code = readmem(ph, start, at - start + 0x40)
    lines = [f"mark {at:#x} start {start:#x}", f"prologue {code[:32].hex()}"]
    jumps = []
    for insn in md.disasm(code, start):
        if insn.mnemonic.startswith("j") or insn.mnemonic in {"call", "ret", "cmp", "test"}:
            jumps.append(f"{insn.address:#x} {insn.bytes.hex():18} {insn.mnemonic} {insn.op_str}")
        if insn.address >= at:
            break
    lines.extend(jumps[-80:])
    # callers: E8 to start
    callers = []
    for i in range(len(blob) - 5):
        if blob[i] != 0xE8:
            continue
        rel32 = int.from_bytes(blob[i + 1 : i + 5], "little", signed=True)
        target = base + i + 5 + rel32
        if start <= target < start + 16:
            callers.append(base + i)
    lines.append("callers " + " ".join(hex(c) for c in callers[:8]))
    for caller in callers[:8]:
        off = caller - base
        lines.append(f"--- caller {caller:#x} ---")
        for insn in md.disasm(
            blob[max(0, off - 0x20) : off + 0x10],
            base + max(0, off - 0x20),
        ):
            lines.append(
                f"{insn.address:#x} {insn.bytes.hex():18} "
                f"{insn.mnemonic} {insn.op_str}"
            )
    k32.CloseHandle(ph)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(lines[0], "jumps", len(jumps), "callers", len(callers))


def find_mark(handle):
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    while addr < 0x80000000:
        if k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        size = int(mbi.RegionSize)
        base = int(mbi.BaseAddress or 0)
        if int(mbi.State) == 0x1000 and int(mbi.Protect) & 0xF0 and 0 < size <= 8 * 1024 * 1024:
            blob = readmem(handle, base, size)
            i = blob.find(MARK)
            if i >= 0:
                return base + i, blob, base
        addr = base + max(size, 1)
    raise SystemExit("mark not found")


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
