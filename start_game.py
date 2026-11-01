"""Start GundamOnline_CHINA.exe without the launcher.

The client reports internal code 49236 when it is not running as administrator,
and 49235 when a firewall blocks it. This script requests elevation, allows
the program through the firewall, then starts it the way patcher.exe does.
"""

import ctypes
import os
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parent
XGG_ERROR_MARKER = bytes.fromhex("c784243008000012000000")
XGG_VERSION_CHECK_FROM_MARKER = 0xAE

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
EXECUTABLE_PAGES = {0x10, 0x20, 0x40, 0x80}
CREATE_SUSPENDED = 0x00000004


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


def find_exe() -> Path:
    found = [
        path
        for path in (ROOT / "launcher").rglob("GundamOnline_CHINA.exe")
        if path.parent.name == "GundamOnline"
    ]
    if not found:
        raise SystemExit("GundamOnline_CHINA.exe was not found")
    return found[0]


def elevate_self() -> None:
    if os.environ.get("GUNDAM_NO_ELEVATE") == "1":
        return
    if ctypes.windll.shell32.IsUserAnAdmin():
        return
    params = " ".join(f'"{arg}"' for arg in sys.argv)
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1
    )
    if rc <= 32:
        raise SystemExit(f"elevation failed ({rc})")
    raise SystemExit(0)


def allow_firewall(exe: Path) -> None:
    for direction in ("in", "out"):
        subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name=GundamOnline China {direction}",
                f"dir={direction}",
                "action=allow",
                f"program={exe}",
                "enable=yes",
            ],
            check=False,
            capture_output=True,
        )


def patch_xgg_startup(
    pid: int, timeout: float = 12.0, process_handle: int | None = None
) -> int | None:
    """Neutralize the unpacked user-mode XGG startup gate before it runs."""
    kernel32 = ctypes.windll.kernel32
    access = (
        PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
    )
    process = kernel32.OpenProcess(access, False, pid)
    if not process:
        raise OSError(ctypes.get_last_error(), "OpenProcess")

    ntdll = ctypes.windll.ntdll
    pulsed = process_handle is not None
    suspended = pulsed
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if pulsed:
                ntdll.NtResumeProcess(process_handle)
                suspended = False
                time.sleep(0.002)
                ntdll.NtSuspendProcess(process_handle)
                suspended = True
            address = 0x10000
            mbi = MEMORY_BASIC_INFORMATION()
            while address < 0x80000000:
                queried = kernel32.VirtualQueryEx(
                    process,
                    ctypes.c_void_p(address),
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi),
                )
                if not queried:
                    break
                base = int(mbi.BaseAddress or 0)
                size = int(mbi.RegionSize)
                protect = int(mbi.Protect)
                executable = (protect & 0xFF) in EXECUTABLE_PAGES
                readable = not (protect & (PAGE_GUARD | PAGE_NOACCESS))
                if (
                    mbi.State == MEM_COMMIT
                    and executable
                    and readable
                    and 0 < size <= 16 * 1024 * 1024
                ):
                    data = ctypes.create_string_buffer(size)
                    count = ctypes.c_size_t()
                    if kernel32.ReadProcessMemory(
                        process,
                        ctypes.c_void_p(base),
                        data,
                        size,
                        ctypes.byref(count),
                    ):
                        offset = data.raw[: count.value].find(XGG_ERROR_MARKER)
                        if offset >= 0:
                            marker = base + offset
                            target = marker - XGG_VERSION_CHECK_FROM_MARKER
                            original = data.raw[
                                offset
                                - XGG_VERSION_CHECK_FROM_MARKER : offset
                                - XGG_VERSION_CHECK_FROM_MARKER
                                + 5
                            ]
                            if original != bytes.fromhex("3d04080000"):
                                raise RuntimeError(
                                    f"unexpected version check {original.hex()}"
                                )
                            old_protect = wintypes.DWORD()
                            if not kernel32.VirtualProtectEx(
                                process,
                                ctypes.c_void_p(target),
                                5,
                                0x40,
                                ctypes.byref(old_protect),
                            ):
                                raise OSError(
                                    ctypes.get_last_error(), "VirtualProtectEx"
                                )
                            # mov eax,0x804 -- select a version the client accepts.
                            patch = ctypes.create_string_buffer(
                                bytes.fromhex("b804080000")
                            )
                            written = ctypes.c_size_t()
                            ok = kernel32.WriteProcessMemory(
                                process,
                                ctypes.c_void_p(target),
                                patch,
                                5,
                                ctypes.byref(written),
                            )
                            restore = wintypes.DWORD()
                            kernel32.VirtualProtectEx(
                                process,
                                ctypes.c_void_p(target),
                                5,
                                old_protect.value,
                                ctypes.byref(restore),
                            )
                            kernel32.FlushInstructionCache(
                                process, ctypes.c_void_p(target), 5
                            )
                            if not ok or written.value != 5:
                                raise OSError(
                                    ctypes.get_last_error(), "WriteProcessMemory"
                                )
                            if pulsed:
                                ntdll.NtResumeProcess(process_handle)
                                suspended = False
                            return target
                address = base + max(size, 1)
            if not pulsed:
                time.sleep(0.01)
    finally:
        if suspended:
            ntdll.NtResumeProcess(process_handle)
        kernel32.CloseHandle(process)
    return None


def capture_dialog(pid: int) -> str:
    user32 = ctypes.windll.user32
    time.sleep(7)
    found: list[str] = []

    def read_text(hwnd: int) -> str:
        buf = ctypes.create_unicode_buffer(2000)
        user32.SendMessageW(hwnd, 0x000D, 2000, buf)
        return buf.value

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def on_child(hwnd, _lp):
        text = read_text(hwnd).strip()
        if text:
            found.append(text)
        return True

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def on_top(hwnd, _lp):
        proc = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(proc))
        if proc.value != pid:
            return True
        title = read_text(hwnd).strip()
        if title:
            found.append(title)
        user32.EnumChildWindows(hwnd, on_child, 0)
        return True

    user32.EnumWindows(on_top, 0)
    return "\n".join(found)


def main() -> None:
    elevate_self()
    exe = find_exe()
    allow_firewall(exe)
    print(f"start {exe}")
    proc = subprocess.Popen([str(exe), "./data/"], cwd=exe.parent)
    patched = None
    report = ROOT / "server" / "launch_result.txt"
    result = capture_dialog(proc.pid)
    report.write_text(
        f"pid={proc.pid}\npatched={patched!r}\nreturn={proc.poll()!r}\n{result}",
        encoding="utf-8",
    )
    print("launched", proc.pid)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        main()
    except Exception:
        import traceback

        (ROOT / "server" / "startup_error.txt").write_text(
            traceback.format_exc(), encoding="utf-8"
        )
        raise
