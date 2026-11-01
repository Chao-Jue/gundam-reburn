"""Find the instruction that returns status 0xffff0002 inside the unpacked XGG image."""

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

import capstone

EXE = list(Path(r"D:\project\gundam-reburn\launcher\gundam").rglob("GundamOnline_CHINA.exe"))[0]
OUT = Path(r"D:\project\gundam-reburn\server\os_status.txt")
SIG = bytes.fromhex("83f803c68424ec000000010f87")
NEEDLES = {
    "mov": bytes.fromhex("b80200ffff"),
    "push": bytes.fromhex("680200ffff"),
    "code": (49236).to_bytes(4, "little"),
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
    hit, alloc, end = locate(ph)
    lines = [f"hit {hit:#x} {alloc:#x}-{end:#x}"]
    # prologue: walk back over executable bytes to a CC pad
    back = readmem(ph, hit - 0x500, 0x500)
    pad = back.rfind(b"\xcc\xcc")
    lines.append(f"pad {hit - 0x500 + pad:#x}" if pad >= 0 else "pad none")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    regions = []
    addr = alloc
    mbi = MEMORY_BASIC_INFORMATION()
    while addr < end:
        if k32.VirtualQueryEx(ph, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        size = int(mbi.RegionSize)
        base = int(mbi.BaseAddress or 0)
        if int(mbi.State) == 0x1000 and int(mbi.Protect) & 0xF0 and size > 0:
            regions.append((base, readmem(ph, base, size)))
        addr = base + max(size, 1)
    shown = 0
    for name, needle in NEEDLES.items():
        for base, blob in regions:
            start = 0
            while shown < 30:
                i = blob.find(needle, start)
                if i < 0:
                    break
                at = base + i
                lines.append(f"--- {name} {at:#x} ---")
                window = blob[max(0, i - 0x18) : i + 0x28]
                origin = at - (i - max(0, i - 0x18))
                for insn in md.disasm(window, origin):
                    mark = " <" if insn.address == at else ""
                    lines.append(f"{insn.address:#x} {insn.bytes.hex():18} {insn.mnemonic} {insn.op_str}{mark}")
                shown += 1
                start = i + 1
    k32.CloseHandle(ph)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("shown", shown, "pad", lines[1])


def locate(handle):
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    while addr < 0x80000000:
        if k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        size = int(mbi.RegionSize)
        base = int(mbi.BaseAddress or 0)
        if int(mbi.State) == 0x1000 and int(mbi.Protect) & 0xF0 and 0 < size <= 16 * 1024 * 1024:
            blob = readmem(handle, base, size)
            i = blob.find(SIG)
            if i >= 0:
                alloc = int(mbi.AllocationBase or base)
                end = base + size
                probe = end
                while probe < alloc + 0x800000:
                    if k32.VirtualQueryEx(handle, ctypes.c_void_p(probe), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
                        break
                    if int(mbi.AllocationBase or 0) != alloc:
                        break
                    end = int(mbi.BaseAddress or 0) + int(mbi.RegionSize)
                    probe = end
                return base + i, alloc, end
        addr = base + max(size, 1)
    raise SystemExit("no sig")


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
