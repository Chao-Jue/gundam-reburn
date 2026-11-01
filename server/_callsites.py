"""Find every relative call into the XGG error dialog function."""

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

import capstone

EXE = list(Path(r"D:\project\gundam-reburn\launcher\gundam").rglob("GundamOnline_CHINA.exe"))[0]
OUT = Path(r"D:\project\gundam-reburn\server\os_callsites.txt")
SIG = bytes.fromhex("83f803c68424ec000000010f87")
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
    if not k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)):
        return b""
    return buf.raw[: got.value]


def main() -> None:
    proc = subprocess.Popen([str(EXE), "./data/"], cwd=str(EXE.parent))
    for _ in range(40):
        time.sleep(0.25)
        if dialog(proc.pid):
            break
    ph = k32.OpenProcess(0x0410, False, proc.pid)
    hit, base, size = find_sig(ph)
    lines = [f"pid {proc.pid} hit {hit:#x} base {base:#x} size {size:#x}"]
    blob = readmem(ph, base, size)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    rel = hit - base
    lines.append("--- function ---")
    for insn in md.disasm(blob[rel - 0x80 : rel + 0x20], hit - 0x80):
        lines.append(f"{insn.address:#x} {insn.bytes.hex():20} {insn.mnemonic} {insn.op_str}")
        if insn.address > hit:
            break
    # relative calls whose target lands just before the signature
    window_lo = hit - 0x180
    window_hi = hit - 0x20
    sites = []
    for i in range(len(blob) - 5):
        if blob[i] != 0xE8:
            continue
        rel32 = int.from_bytes(blob[i + 1 : i + 5], "little", signed=True)
        target = base + i + 5 + rel32
        if window_lo <= target <= window_hi:
            sites.append((base + i, target))
    lines.append(f"sites {len(sites)}")
    for at, target in sites[:12]:
        off = at - base
        lines.append(f"--- call {at:#x} -> {target:#x} ---")
        for insn in md.disasm(blob[max(0, off - 0x28) : off + 8], base + max(0, off - 0x28)):
            mark = " <" if insn.address == at else ""
            lines.append(f"{insn.address:#x} {insn.bytes.hex():18} {insn.mnemonic} {insn.op_str}{mark}")
    k32.CloseHandle(ph)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("sites", len(sites), "hit", hex(hit))


def find_sig(handle):
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
                # span consecutive regions of this allocation
                end = base + size
                probe = end
                while probe < 0x80000000:
                    if k32.VirtualQueryEx(handle, ctypes.c_void_p(probe), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
                        break
                    if int(mbi.AllocationBase or 0) != alloc:
                        break
                    end = int(mbi.BaseAddress or 0) + int(mbi.RegionSize)
                    probe = end
                return alloc + (base - alloc) + i if False else base + i, alloc, end - alloc
        addr = base + max(size, 1)
    raise SystemExit("signature not found")


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
