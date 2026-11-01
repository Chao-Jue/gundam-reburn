"""Print stack returns inside the unpacked XGG image and the dialog function prologue."""

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

import capstone

EXE = list(Path(r"D:\project\gundam-reburn\launcher\gundam").rglob("GundamOnline_CHINA.exe"))[0]
OUT = Path(r"D:\project\gundam-reburn\server\os_who.txt")
SIG = bytes.fromhex("83f803c68424ec000000010f87")
k32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32


class WOW64_FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [
        ("ControlWord", wintypes.DWORD),
        ("StatusWord", wintypes.DWORD),
        ("TagWord", wintypes.DWORD),
        ("ErrorOffset", wintypes.DWORD),
        ("ErrorSelector", wintypes.DWORD),
        ("DataOffset", wintypes.DWORD),
        ("DataSelector", wintypes.DWORD),
        ("RegisterArea", ctypes.c_byte * 80),
        ("Cr0NpxState", wintypes.DWORD),
    ]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", wintypes.DWORD),
        ("Dr0", wintypes.DWORD),
        ("Dr1", wintypes.DWORD),
        ("Dr2", wintypes.DWORD),
        ("Dr3", wintypes.DWORD),
        ("Dr6", wintypes.DWORD),
        ("Dr7", wintypes.DWORD),
        ("FloatSave", WOW64_FLOATING_SAVE_AREA),
        ("SegGs", wintypes.DWORD),
        ("SegFs", wintypes.DWORD),
        ("SegEs", wintypes.DWORD),
        ("SegDs", wintypes.DWORD),
        ("Edi", wintypes.DWORD),
        ("Esi", wintypes.DWORD),
        ("Ebx", wintypes.DWORD),
        ("Edx", wintypes.DWORD),
        ("Ecx", wintypes.DWORD),
        ("Eax", wintypes.DWORD),
        ("Ebp", wintypes.DWORD),
        ("Eip", wintypes.DWORD),
        ("SegCs", wintypes.DWORD),
        ("EFlags", wintypes.DWORD),
        ("Esp", wintypes.DWORD),
        ("SegSs", wintypes.DWORD),
        ("ExtendedRegisters", ctypes.c_byte * 512),
    ]


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
    k32.Wow64GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
    k32.Wow64GetThreadContext.restype = wintypes.BOOL
    proc = subprocess.Popen([str(EXE), "./data/"], cwd=str(EXE.parent))
    tid = 0
    for _ in range(40):
        time.sleep(0.25)
        tid = dialog_tid(proc.pid)
        if tid:
            break
    ph = k32.OpenProcess(0x0410, False, proc.pid)
    hit, alloc, end = locate(ph)
    lines = [f"hit {hit:#x} alloc {alloc:#x}-{end:#x} tid {tid}"]
    head = readmem(ph, hit - 0x160, 0x40)
    lines.append(head.hex())
    th = k32.OpenThread(0x004A, False, tid)
    k32.SuspendThread(th)
    ctx = WOW64_CONTEXT()
    ctx.ContextFlags = 0x10007
    k32.Wow64GetThreadContext(th, ctypes.byref(ctx))
    stack = readmem(ph, ctx.Esp, 0x3000)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    seen = set()
    for i in range(0, len(stack) - 3, 4):
        val = int.from_bytes(stack[i : i + 4], "little")
        if not (alloc <= val < end) or val in seen:
            continue
        prev = readmem(ph, val - 6, 6)
        if len(prev) < 6:
            continue
        if prev[1] == 0xE8 or prev[0] in (0xE8, 0xFF) or prev[5] == 0xE8:
            seen.add(val)
            lines.append(f"ret {val:#x} prev {prev.hex()}")
            blob = readmem(ph, val - 0x18, 0x20)
            for insn in md.disasm(blob, val - 0x18):
                mark = " <" if insn.address + insn.size == val else ""
                lines.append(f"  {insn.address:#x} {insn.mnemonic} {insn.op_str}{mark}")
                if len(lines) > 220:
                    break
        if len(seen) >= 15:
            break
    k32.ResumeThread(th)
    k32.CloseHandle(th)
    k32.CloseHandle(ph)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("seen", len(seen))


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


def dialog_tid(pid):
    found = [0]

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def on_top(hwnd, _lp):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        tid = user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid:
            buf = ctypes.create_unicode_buffer(40)
            user32.GetWindowTextW(hwnd, buf, 40)
            if "发现错误" in buf.value:
                found[0] = int(tid)
                return False
        return True

    user32.EnumWindows(on_top, 0)
    return found[0]


if __name__ == "__main__":
    main()
