"""Walk the error-dialog thread back into the unpacked XGG code."""

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

EXE = list(Path(r"D:\project\gundam-reburn\launcher\gundam").rglob("GundamOnline_CHINA.exe"))[0]
OUT = Path(r"D:\project\gundam-reburn\server\os_stack.txt")
k32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

THREAD_GET_CONTEXT = 0x0008
THREAD_SUSPEND_RESUME = 0x0002
THREAD_QUERY_INFORMATION = 0x0040
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
WOW64_CONTEXT_FULL = 0x10007


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


def main() -> None:
    k32.Wow64GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
    k32.Wow64GetThreadContext.restype = wintypes.BOOL
    proc = subprocess.Popen([str(EXE), "./data/"], cwd=str(EXE.parent))
    hwnd = 0
    tid = 0
    for _ in range(40):
        time.sleep(0.25)
        hwnd, tid = find_dialog(proc.pid)
        if hwnd:
            break
    lines = [f"pid {proc.pid} hwnd {hwnd:#x} tid {tid}"]
    if not tid:
        OUT.write_text("\n".join(lines), encoding="utf-8")
        print("no dialog")
        return
    ph = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, proc.pid)
    th = k32.OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, False, tid)
    k32.SuspendThread(th)
    ctx = WOW64_CONTEXT()
    ctx.ContextFlags = WOW64_CONTEXT_FULL
    ok = k32.Wow64GetThreadContext(th, ctypes.byref(ctx))
    lines.append(f"ctx {ok} err {k32.GetLastError()} eip {ctx.Eip:#x} esp {ctx.Esp:#x} ebp {ctx.Ebp:#x}")
    raw = readmem(ph, ctx.Esp, 0x800)
    addrs = []
    for i in range(0, len(raw) - 3, 4):
        val = int.from_bytes(raw[i : i + 4], "little")
        if 0x10000 <= val < 0x80000000:
            addrs.append((ctx.Esp + i, val))
    # keep addresses that sit in executable pages
    interesting = []
    for slot, val in addrs:
        prot = protect(ph, val)
        if prot & 0xF0:
            interesting.append((slot, val, prot))
    lines.append(f"exec refs {len(interesting)}")
    for slot, val, prot in interesting[:40]:
        lines.append(f"{slot:#x} -> {val:#x} prot {prot:#x}")
    k32.ResumeThread(th)
    k32.CloseHandle(th)
    k32.CloseHandle(ph)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("refs", len(interesting))


def find_dialog(pid):
    found = [0, 0]

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def on_top(hwnd, _lp):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value != pid:
            return True
        buf = ctypes.create_unicode_buffer(80)
        user32.GetWindowTextW(hwnd, buf, 80)
        if "发现错误" in buf.value:
            found[0] = int(hwnd)
            user32.GetWindowThreadProcessId.restype = wintypes.DWORD
            found[1] = int(user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner)))
            return False
        return True

    user32.EnumWindows(on_top, 0)
    return found[0], found[1]


def readmem(handle, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
    return buf.raw[: got.value]


def protect(handle, addr):
    mbi = MEMORY_BASIC_INFORMATION()
    if k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
        return 0
    if int(mbi.State) != 0x1000:
        return 0
    return int(mbi.Protect)


if __name__ == "__main__":
    main()
