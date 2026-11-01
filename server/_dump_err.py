"""Dump the decrypted error-message table and nearby error codes."""

import ctypes
from ctypes import wintypes

PID = 47640
k32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


def read(handle, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
    if not ok:
        raise OSError(k32.GetLastError())
    return buf.raw[: got.value]


def main() -> None:
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, PID)
    if not handle:
        raise SystemExit(f"open {k32.GetLastError()}")
    mods = (ctypes.c_void_p * 256)()
    needed = wintypes.DWORD()
    psapi.EnumProcessModules(handle, mods, ctypes.sizeof(mods), ctypes.byref(needed))
    count = needed.value // ctypes.sizeof(ctypes.c_void_p)
    info = MODULEINFO()
    name = ctypes.create_unicode_buffer(260)
    for i in range(count):
        base = mods[i]
        psapi.GetModuleInformation(handle, base, ctypes.byref(info), ctypes.sizeof(info))
        psapi.GetModuleBaseNameW(handle, base, name, 260)
        start = int(info.lpBaseOfDll or 0)
        end = start + int(info.SizeOfImage)
        if start <= 0x1AFBA8 < end:
            print(f"owner {name.value} {start:#x} size {info.SizeOfImage:#x}")
    data = read(handle, 0x1AF700, 0x1200)
    text = data.decode("utf-16le", errors="replace")
    print("---TEXT---")
    print(text.replace("\x00", " "))
    for label, needle in (("49236", (49236).to_bytes(4, "little")), ("ffff0002", bytes.fromhex("0200ffff"))):
        blob = read(handle, 0x400000, 0xE00000)
        start = 0
        n = 0
        while n < 12:
            i = blob.find(needle, start)
            if i < 0:
                break
            print(label, hex(0x400000 + i))
            start = i + 4
            n += 1
    k32.CloseHandle(handle)


if __name__ == "__main__":
    main()
