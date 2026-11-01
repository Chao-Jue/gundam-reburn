"""Find who calls the XGG error dialog, in memory and in the exe file."""

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

import capstone

EXE = list(Path(r"D:\project\gundam-reburn\launcher\gundam").rglob("GundamOnline_CHINA.exe"))[0]
OUT = Path(r"D:\project\gundam-reburn\server\os_caller.txt")
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
    file_hits = []
    data = EXE.read_bytes()
    start = 0
    while len(file_hits) < 5:
        i = data.find(SIG, start)
        if i < 0:
            break
        file_hits.append(i)
        start = i + 1
    lines = ["file " + (" ".join(hex(h) for h in file_hits) or "none")]
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
    hit = None
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    while addr < 0x80000000:
        if k32.VirtualQueryEx(ph, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        size = int(mbi.RegionSize)
        base = int(mbi.BaseAddress or 0)
        prot = int(mbi.Protect)
        if int(mbi.State) == 0x1000 and prot & 0xF0 and 0 < size <= 16 * 1024 * 1024:
            blob = readmem(ph, base, size)
            i = blob.find(SIG)
            if i >= 0:
                hit = base + i
                break
        addr = base + max(size, 1)
    lines.append(f"mem {hit:#x}" if hit else "mem none")
    if hit:
        th = k32.OpenThread(0x004A, False, tid)
        k32.SuspendThread(th)
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = 0x10007
        k32.Wow64GetThreadContext(th, ctypes.byref(ctx))
        stack = readmem(ph, ctx.Esp, 0x2000)
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        # function starts shortly before the signature
        fn = hit - 0x90
        callers = []
        for i in range(0, len(stack) - 3, 4):
            val = int.from_bytes(stack[i : i + 4], "little")
            if not (0x10000 <= val < 0x80000000):
                continue
            prev = readmem(ph, val - 5, 5)
            if len(prev) == 5 and prev[0] == 0xE8:
                rel = int.from_bytes(prev[1:], "little", signed=True)
                target = val + rel
                if hit - 0x200 <= target <= hit:
                    callers.append((ctx.Esp + i, val, target))
        lines.append(f"callers {len(callers)}")
        for slot, val, target in callers[:6]:
            lines.append(f"stack {slot:#x} ret {val:#x} calls {target:#x}")
            blob = readmem(ph, val - 0x30, 0x50)
            for insn in md.disasm(blob, val - 0x30):
                mark = " <" if insn.address + insn.size == val else ""
                lines.append(f"  {insn.address:#x} {insn.bytes.hex():18} {insn.mnemonic} {insn.op_str}{mark}")
        k32.ResumeThread(th)
        k32.CloseHandle(th)
    k32.CloseHandle(ph)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[:8]))


def dialog_tid(pid):
    found = [0]

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def on_top(hwnd, _lp):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        tid = user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value != pid:
            return True
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
