"""Find pointers to the decrypted OS-error string inside the running game."""

import ctypes
from ctypes import wintypes

PID = 51740
HITS = [0x1AFBA8, 0x168D35E, 0x22405A0, 0x6925E4C, 0x716FC14]
k32 = ctypes.windll.kernel32

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100


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
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, PID)
    if not handle:
        raise SystemExit(f"open {k32.GetLastError()}")
    for hit in HITS:
        buf = ctypes.create_unicode_buffer(180)
        read = ctypes.c_size_t()
        k32.ReadProcessMemory(handle, ctypes.c_void_p(hit - 80), buf, 160, ctypes.byref(read))
        text = buf.value.replace("\n", " | ")
        print(f"TEXT {hit:#x} {text[:180]}")
    ptr_hits: list[tuple[int, int]] = []
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    needles = [hit.to_bytes(4, "little") for hit in HITS]
    while addr < 0x80000000 and len(ptr_hits) < 40:
        if k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        size = int(mbi.RegionSize)
        base = int(mbi.BaseAddress or 0)
        prot = int(mbi.Protect)
        if mbi.State == MEM_COMMIT and not (prot & PAGE_NOACCESS) and not (prot & PAGE_GUARD) and 0 < size <= 16 * 1024 * 1024:
            raw = ctypes.create_string_buffer(size)
            got = ctypes.c_size_t()
            if k32.ReadProcessMemory(handle, ctypes.c_void_p(base), raw, size, ctypes.byref(got)):
                data = raw.raw[: got.value]
                for hit, needle in zip(HITS, needles):
                    start = 0
                    while len(ptr_hits) < 40:
                        i = data.find(needle, start)
                        if i < 0:
                            break
                        ptr_hits.append((base + i, hit))
                        start = i + 4
        addr = base + max(size, 1)
    k32.CloseHandle(handle)
    for where, target in ptr_hits:
        print(f"PTR {where:#x} -> {target:#x}")


if __name__ == "__main__":
    main()
