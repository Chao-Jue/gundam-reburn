#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""只测「CPS.sys 这个内核驱动能不能加载」——把驱动问题从游戏里彻底剥离出来。

用法（普通权限即可，会自己弹 UAC 提权）：
    python tools/drv_load_probe.py
    python tools/drv_load_probe.py --no-elevate    # 已经是管理员时用

它做的事（全部只围绕 *驱动加载*，不碰游戏、不改被保护模块）：
    1. 把 tools/../server/CPS_extracted.sys 复制到 C:\\Windows\\SysWOW64\\CPS.sys
       （就是保护模块自己用的路径，32 位进程的 SystemDirectory 被 WOW64 重定向）
    2. OpenSCManagerW -> CreateServiceW("CPS_PROBE", 内核驱动, 按需启动)
       —— 复刻保护模块的调用，但换个服务名，避免干扰
    3. StartServiceW  -> 记录 GetLastError()（**关键：系统给的真实拒绝原因**）
    4. QueryServiceStatusEx -> 拿 dwWin32ExitCode / dwServiceSpecificExitCode
       （驱动加载失败的真实状态码常常在这里，比如 0xC0000428 = 镜像哈希不被接受）
    5. 顺手试 CreateFileW("\\\\.\\CPS") 看设备对象有没有建出来
    6. DeleteService 收尾（不动那个 .sys 文件，留着方便你再看）

报告同时写到 server/drv_load_report.txt。
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC_SYS = ROOT / "server" / "CPS_extracted.sys"
DST_SYS = Path(r"C:\Windows\SysWOW64\CPS.sys")
REPORT = ROOT / "server" / "drv_load_report.txt"

SERVICE_NAME = "CPS_PROBE"
# 保护模块用的是 \??\ 前缀的 NT 路径，这里照抄
IMAGE_PATH = r"\??\C:\WINDOWS\SysWOW64\CPS.sys"

SC_MANAGER_ALL_ACCESS = 0x000F003F
SERVICE_ALL_ACCESS = 0x000F01FF
SERVICE_KERNEL_DRIVER = 0x00000001
SERVICE_DEMAND_START = 0x00000003
SERVICE_ERROR_IGNORE = 0x00000000
SC_STATUS_PROCESS_INFO = 0

SERVICE_STATE = {
    1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING", 4: "RUNNING",
    5: "CONTINUE_PENDING", 6: "PAUSE_PENDING", 7: "PAUSED",
}

# 常见的内核驱动加载失败码（人话对照）
LOAD_ERRORS = {
    2: "ERROR_FILE_NOT_FOUND —— 镜像文件找不到/打不开",
    5: "ERROR_ACCESS_DENIED —— 权限不足（未提权）",
    87: "ERROR_INVALID_PARAMETER",
    1058: "ERROR_SERVICE_DISABLED —— 服务被禁用",
    1060: "ERROR_SERVICE_DOES_NOT_EXIST",
    1066: "ERROR_SERVICE_SPECIFIC_ERROR —— 见 dwServiceSpecificExitCode",
    577: "ERROR_DRIVER_BLOCKED —— 被驱动阻止策略/CI 拦下",
    1275: "ERROR_DRIVER_FAILED_PRIOR_UNLOAD",
    0x800704EC: "ERROR_SERVICE_DISABLED(HRESULT 形式)",
    0xC0000428: "STATUS_INVALID_IMAGE_HASH —— 镜像哈希不被接受（签名级别不够/被阻止列表命中）",
    0xC0000365: "STATUS_FAILED_DRIVER_ENTRY / CI 相关",
    0xC0000369: "STATUS_IMAGE_CERT_REVOKED 之类",
    0xC0000603: "STATUS_INVALID_IMAGE_HASH",
    0xC0000121: "STATUS_DRIVER_ENTRYPOINT_NOT_FOUND",
}

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wt.DWORD),
        ("dwCurrentState", wt.DWORD),
        ("dwControlsAccepted", wt.DWORD),
        ("dwWin32ExitCode", wt.DWORD),
        ("dwServiceSpecificExitCode", wt.DWORD),
        ("dwCheckPoint", wt.DWORD),
        ("dwWaitHint", wt.DWORD),
        ("dwProcessId", wt.DWORD),
        ("dwServiceFlags", wt.DWORD),
    ]


advapi32.OpenSCManagerW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, wt.DWORD]
advapi32.OpenSCManagerW.restype = wt.HANDLE
advapi32.CreateServiceW.argtypes = [
    wt.HANDLE, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD,
    wt.LPCWSTR, wt.LPCWSTR, ctypes.POINTER(wt.DWORD), wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR,
]
advapi32.CreateServiceW.restype = wt.HANDLE
advapi32.OpenServiceW.argtypes = [wt.HANDLE, wt.LPCWSTR, wt.DWORD]
advapi32.OpenServiceW.restype = wt.HANDLE
advapi32.StartServiceW.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.LPCWSTR)]
advapi32.StartServiceW.restype = wt.BOOL
advapi32.QueryServiceStatusEx.argtypes = [
    wt.HANDLE, ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), wt.DWORD,
    ctypes.POINTER(wt.DWORD),
]
advapi32.QueryServiceStatusEx.restype = wt.BOOL
advapi32.DeleteService.argtypes = [wt.HANDLE]
advapi32.DeleteService.restype = wt.BOOL
advapi32.CloseServiceHandle.argtypes = [wt.HANDLE]
advapi32.CloseServiceHandle.restype = wt.BOOL


class _SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wt.HWND),
        ("lpVerb", wt.LPCWSTR), ("lpFile", wt.LPCWSTR), ("lpParameters", wt.LPCWSTR),
        ("lpDirectory", wt.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wt.HINSTANCE),
        ("lpIDList", ctypes.c_void_p), ("lpClass", wt.LPCWSTR), ("hkeyClass", wt.HKEY),
        ("dwHotKey", wt.DWORD), ("hIcon", wt.HANDLE), ("hProcess", wt.HANDLE),
    ]


def is_admin() -> bool:
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def relaunch_elevated() -> int:
    """用 runas 重新启动自己（带 --no-elevate 防递归），等它跑完。"""
    sei = _SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = 0x00000040 | 0x00000100  # NOCLOSEPROCESS | NOASYNC
    sei.lpVerb = "runas"
    sei.lpFile = sys.executable
    sei.lpParameters = f'"{Path(__file__).resolve()}" --no-elevate'
    sei.lpDirectory = str(ROOT)
    sei.nShow = 1
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        err = ctypes.get_last_error()
        print(f"[X] 提权失败（错误码 {err}；1223 = 你点了“否”）。"
              f"也可以自己用管理员开一个终端再跑本脚本。")
        return 3
    kernel32.WaitForSingleObject(sei.hProcess, 300_000)
    code = wt.DWORD()
    kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(code))
    kernel32.CloseHandle(sei.hProcess)
    return int(code.value)


def err_text(code: int) -> str:
    if code in LOAD_ERRORS:
        return LOAD_ERRORS[code]
    try:
        return ctypes.FormatError(code).strip()
    except Exception:  # noqa: BLE001
        return ""


def run_probe(lines: list[str]) -> int:
    def emit(s: str = "") -> None:
        print(s)
        lines.append(s)

    emit("=" * 70)
    emit(" CPS.sys 驱动加载探针")
    emit("=" * 70)
    emit(f"admin = {is_admin()}")

    if DST_SYS.exists():
        emit(f"[i] 目标位置已存在文件，将被覆盖: {DST_SYS}")
    if not SRC_SYS.exists():
        emit(f"[X] 找不到源驱动 {SRC_SYS}（用 tools/run_hooked.py 抓一个先）")
        return 4
    blob = SRC_SYS.read_bytes()
    emit(f"[i] 源驱动 {SRC_SYS.name}  {len(blob)} 字节")
    emit(f"    md5    = {hashlib.md5(blob).hexdigest()}")
    emit(f"    sha256 = {hashlib.sha256(blob).hexdigest()}")
    try:
        DST_SYS.write_bytes(blob)
        emit(f"[+] 已复制到 {DST_SYS}")
    except Exception as e:  # noqa: BLE001
        emit(f"[X] 复制失败: {e}")
        return 5

    # ---- 1. 打开 SCM ----
    hscm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
    if not hscm:
        emit(f"[X] OpenSCManagerW 失败: {ctypes.get_last_error()}")
        return 6
    emit()
    emit("[1] OpenSCManagerW -> OK")

    # 先清掉可能存在的同名服务
    old = advapi32.OpenServiceW(hscm, SERVICE_NAME, SERVICE_ALL_ACCESS)
    if old:
        advapi32.DeleteService(old)
        advapi32.CloseServiceHandle(old)
        emit(f"[i] 已删除旧的 {SERVICE_NAME} 服务")

    # ---- 2. 创建服务 ----
    hs = advapi32.CreateServiceW(
        hscm, SERVICE_NAME, SERVICE_NAME, SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        IMAGE_PATH, None, None, None, None, None)
    if not hs:
        e = ctypes.get_last_error()
        emit(f"[X] CreateServiceW 失败: {e}  0x{e & 0xffffffff:08X}  {err_text(e)}")
        advapi32.CloseServiceHandle(hscm)
        return 7
    emit(f"[2] CreateServiceW(\"{SERVICE_NAME}\", 内核驱动, 按需启动) -> OK")
    emit(f"    ImagePath = {IMAGE_PATH}")

    # ---- 3. 启动服务（关键） ----
    rc = advapi32.StartServiceW(hs, 0, None)
    start_err = ctypes.get_last_error() if not rc else 0
    emit()
    if rc:
        emit("[3] StartServiceW -> OK  ★ 驱动加载成功！")
    else:
        e = start_err
        emit(f"[3] StartServiceW -> 失败  GetLastError = {e}  (0x{e & 0xffffffff:08X})")
        emit(f"    {err_text(e)}")

    # ---- 4. 查询服务状态（驱动的真实加载状态常在这里） ----
    buf = (ctypes.c_ubyte * 1024)()
    need = wt.DWORD()
    if advapi32.QueryServiceStatusEx(hs, SC_STATUS_PROCESS_INFO, buf,
                                     ctypes.sizeof(buf), ctypes.byref(need)):
        st = SERVICE_STATUS_PROCESS.from_buffer(buf)
        emit()
        emit("[4] QueryServiceStatusEx:")
        emit(f"    CurrentState              = {st.dwCurrentState} "
             f"({SERVICE_STATE.get(st.dwCurrentState, '?')})")
        emit(f"    dwWin32ExitCode           = {st.dwWin32ExitCode} "
             f"(0x{st.dwWin32ExitCode & 0xffffffff:08X})  {err_text(st.dwWin32ExitCode)}")
        emit(f"    dwServiceSpecificExitCode = {st.dwServiceSpecificExitCode} "
             f"(0x{st.dwServiceSpecificExitCode & 0xffffffff:08X})  "
             f"{err_text(st.dwServiceSpecificExitCode)}")
        emit(f"    dwCheckPoint / dwWaitHint = {st.dwCheckPoint} / {st.dwWaitHint}")
    else:
        emit(f"[4] QueryServiceStatusEx 失败: {ctypes.get_last_error()}")

    # ---- 5. 设备对象建出来了吗 ----
    kernel32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                                     wt.DWORD, wt.DWORD, wt.HANDLE]
    kernel32.CreateFileW.restype = wt.HANDLE
    h = kernel32.CreateFileW(r"\\.\CPS", 0xC0000000, 0, None, 3, 0, None)
    if h == wt.HANDLE(-1).value or h == -1:
        emit()
        emit(f"[5] CreateFileW(\"\\\\.\\CPS\") -> 失败, GetLastError = "
             f"{ctypes.get_last_error()}（驱动没起来时这是正常的）")
    else:
        emit()
        emit(f"[5] CreateFileW(\"\\\\.\\CPS\") -> OK, 句柄 {h}  ★ 设备对象存在")
        kernel32.CloseHandle(h)

    # ---- 6. 收尾 ----
    emit()
    emit("[6] 收尾: DeleteService")
    advapi32.DeleteService(hs)
    advapi32.CloseServiceHandle(hs)
    advapi32.CloseServiceHandle(hscm)
    emit(f"[i] 保留 {DST_SYS} 供你后续检查（不想留就自己删）")

    emit()
    emit("-" * 70)
    if rc:
        emit("结论：驱动能加载 -> 保护模块失败的原因在别处（看 XDt 日志）")
    else:
        emit("结论：驱动确实加载不了。上面 [3]/[4] 的错误码就是根因，"
             "可按 server/环境改动记录.md 的思路处理。")
    emit("-" * 70)
    return 0 if rc else 8


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-elevate", action="store_true",
                    help="内部用：已经是管理员时直接跑，不再提权")
    args = ap.parse_args()

    if sys.platform != "win32":
        print("仅 Windows。", file=sys.stderr)
        return 2

    if not args.no_elevate and not is_admin():
        print("[*] 当前不是管理员，准备用 UAC 提权重跑（请点“是”）...")
        rc = relaunch_elevated()
        print(f"\n[*] 提权子进程退出码 = {rc}")
        if REPORT.exists():
            print("[*] ---- 子进程报告 ----")
            print(REPORT.read_text(encoding="utf-8", errors="replace"))
        return rc

    lines: list[str] = []
    rc = run_probe(lines)
    try:
        REPORT.write_text("\n".join(lines), encoding="utf-8")
        print(f"\n[*] 报告已写入 {REPORT}")
    except Exception as e:  # noqa: BLE001
        print(f"[!] 写报告失败: {e}")
    return rc


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass
    raise SystemExit(main())
