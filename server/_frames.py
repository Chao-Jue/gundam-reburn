"""Walk the dialog's stack frames and disassemble the XGG return sites."""

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

import capstone

EXE = list(Path(r"D:\project\gundam-reburn\launcher\gundam").rglob("GundamOnline_CHINA.exe"))[0]
OUT = Path(r"D:\project\gundam-reburn\server\os_frames.txt")
k32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
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


def main() -> None:
    k32.Wow64GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
    k32.Wow64GetThreadContext.restype = wintypes.BOOL
    proc = subprocess.Popen([str(EXE), "./data/"], cwd=str(EXE.parent))
    hwnd, tid = 0, 0
    for _ in range(40):
        time.sleep(0.25)
        hwnd, tid = find_dialog(proc.pid)
        if hwnd:
            break
    lines = [f"pid {proc.pid} tid {tid}"]
    ph = k32.OpenProcess(0x0410, False, proc.pid)
    th = k32.OpenThread(0x004A, False, tid)
    k32.SuspendThread(th)
    ctx = WOW64_CONTEXT()
    ctx.ContextFlags = WOW64_CONTEXT_FULL
    k32.Wow64GetThreadContext(th, ctypes.byref(ctx))
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    lines.append(f"eip {ctx.Eip:#x}")
    ebp = ctx.Ebp
    rets = [ctx.Eip]
    for _ in range(24):
        frame = readmem(ph, ebp, 8)
        if len(frame) < 8:
            break
        saved = int.from_bytes(frame[:4], "little")
        ret = int.from_bytes(frame[4:], "little")
        lines.append(f"frame {ebp:#x} ret {ret:#x}")
        rets.append(ret)
        if saved <= ebp or saved > 0x80000000:
            break
        ebp = saved
    for ret in rets:
        if not (0x2000000 <= ret < 0x75000000):
            continue
        blob = readmem(ph, ret - 0x240, 0x280)
        lines.append(f"--- {ret:#x} ---")
        if not blob:
            lines.append("unreadable")
            continue
        for insn in md.disasm(blob, ret - 0x240):
            mark = " <" if insn.address + insn.size == ret else ""
            lines.append(f"{insn.address:#x} {insn.bytes.hex():20} {insn.mnemonic} {insn.op_str}{mark}")
    k32.ResumeThread(th)
    k32.CloseHandle(th)
    k32.CloseHandle(ph)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("frames written", len(lines))


def find_dialog(pid):
    found = [0, 0]

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def on_top(hwnd, _lp):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        tid = user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value != pid:
            return True
        buf = ctypes.create_unicode_buffer(80)
        user32.GetWindowTextW(hwnd, buf, 80)
        if "发现错误" in buf.value:
            found[0] = int(hwnd)
            found[1] = int(tid)
            return False
        return True

    user32.EnumWindows(on_top, 0)
    return found[0], found[1]


def readmem(handle, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
    return buf.raw[: got.value]


if __name__ == "__main__":
    main()
