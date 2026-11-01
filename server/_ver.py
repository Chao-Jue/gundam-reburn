"""Disassemble the version compare that rejects this operating system."""

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

import capstone

EXE = list(Path(r"D:\project\gundam-reburn\launcher\gundam").rglob("GundamOnline_CHINA.exe"))[0]
OUT = Path(r"D:\project\gundam-reburn\server\os_ver.txt")
MARK = bytes.fromhex("3d040800000f87")
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
    at = find(ph)
    blob = readmem(ph, at - 0x10, 0x80)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    lines = [f"at {at:#x}", blob.hex()]
    for insn in md.disasm(blob[0x10:], at):
        lines.append(f"{insn.address:#x} {insn.bytes.hex():20} {insn.mnemonic} {insn.op_str}")
    # also the ja target
    # ja rel32 is at at+5, opcode 0f 87, rel at at+7
    rel = int.from_bytes(readmem(ph, at + 7, 4), "little", signed=True)
    dest = at + 11 + rel
    lines.append(f"--- ja dest {dest:#x} ---")
    more = readmem(ph, dest, 0x40)
    for insn in md.disasm(more, dest):
        lines.append(f"{insn.address:#x} {insn.bytes.hex():20} {insn.mnemonic} {insn.op_str}")
        if insn.mnemonic == "call" and insn.address > dest + 0x20:
            break
    k32.CloseHandle(ph)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(lines[0])


def find(handle):
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
                return base + i
        addr = base + max(size, 1)
    raise SystemExit("not found")


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
