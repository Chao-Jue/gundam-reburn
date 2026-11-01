"""清理保护模块在系统里留下的 `CPS` 服务键 / 驱动文件残留。

为什么要清理：客户端一旦"骗过"驱动加载（见 tools/run_hooked.py），
保护模块就认为驱动起来了，于是**不再执行它的回收流程**，把 `CPS`
服务键留在系统里。下一次启动时它会走 `OpenService` 而不是
`CreateService` 分支，日志里出现 `Last Error Before Open = 1073`
（ERROR_SERVICE_ALREADY_RUNNING），行为不可复现。

本工具只动"CPS 相关"的东西：服务键的 ImagePath 必须包含 `cps.sys`，
文件必须叫 `CPS.sys`。任何不匹配的一律不碰。

用法:
    python tools/clean_cps.py --dry-run     # 只看会删什么
    python tools/clean_cps.py               # 真删（需要管理员）
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import sys
import winreg

SERVICE = "CPS"
SERVICE_KEY = rf"SYSTEM\CurrentControlSet\Services\{SERVICE}"
FILES = [
    r"C:\Windows\SysWOW64\CPS.sys",
    r"C:\Windows\System32\CPS.sys",
    r"C:\Windows\SysWOW64\drivers\CPS.sys",
    r"C:\Windows\System32\drivers\CPS.sys",
]

SC_MANAGER_ALL_ACCESS = 0xF003F
SERVICE_ALL_ACCESS = 0xF01FF
SERVICE_CONTROL_STOP = 0x00000001

_adv = ctypes.windll.advapi32
_adv.OpenSCManagerW.restype = wt.HANDLE
_adv.OpenSCManagerW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, wt.DWORD]
_adv.OpenServiceW.restype = wt.HANDLE
_adv.OpenServiceW.argtypes = [wt.HANDLE, wt.LPCWSTR, wt.DWORD]
_adv.DeleteService.restype = wt.BOOL
_adv.DeleteService.argtypes = [wt.HANDLE]
_adv.ControlService.restype = wt.BOOL
_adv.ControlService.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p]
_adv.CloseServiceHandle.restype = wt.BOOL
_adv.CloseServiceHandle.argtypes = [wt.HANDLE]


def scm_exists(name: str = SERVICE) -> bool:
    """SCM 是否仍持有这个服务（哪怕注册表键已经没了）。"""
    h = _adv.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
    if not h:
        return False
    try:
        hs = _adv.OpenServiceW(h, name, SERVICE_ALL_ACCESS)
        if not hs:
            return False
        _adv.CloseServiceHandle(hs)
        return True
    finally:
        _adv.CloseServiceHandle(h)


def scm_delete(name: str = SERVICE) -> tuple[bool, str]:
    """走 SCM 正确删除服务（比删注册表键干净：SCM 内部记录也会释放）。"""
    h = _adv.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
    if not h:
        return False, f"OpenSCManagerW 失败 err={ctypes.get_last_error()}"
    hs = None
    try:
        hs = _adv.OpenServiceW(h, name, SERVICE_ALL_ACCESS)
        if not hs:
            return True, "SCM 里不存在"
        st = ctypes.create_string_buffer(36)
        _adv.ControlService(hs, SERVICE_CONTROL_STOP, ctypes.byref(st))  # 尽力停一下
        if not _adv.DeleteService(hs):
            return False, f"DeleteService 失败 err={ctypes.get_last_error()}"
        return True, "已通过 SCM 删除"
    finally:
        if hs:
            _adv.CloseServiceHandle(hs)
        _adv.CloseServiceHandle(h)


def _delete_tree(root, path: str) -> None:
    with winreg.OpenKey(root, path, 0, winreg.KEY_ALL_ACCESS) as key:
        while True:
            try:
                sub = winreg.EnumKey(key, 0)
            except OSError:
                break
            _delete_tree(root, path + "\\" + sub)
    winreg.DeleteKey(root, path)


def inspect() -> tuple[dict, list[str]]:
    """返回 (服务键信息, 存在的驱动文件列表)。"""
    info: dict = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICE_KEY) as k:
            for v in ("ImagePath", "Type", "Start", "DeleteFlag"):
                try:
                    info[v] = winreg.QueryValueEx(k, v)[0]
                except FileNotFoundError:
                    pass
    except FileNotFoundError:
        info = {}
    files = [p for p in FILES if os.path.exists(p)]
    return info, files


def clean(dry: bool = False, verbose: bool = True) -> bool:
    """清理残留。返回是否干净了。"""
    info, files = inspect()
    in_scm = scm_exists()
    ok = True
    if not info and not files and not in_scm:
        if verbose:
            print("[=] 没有 CPS 残留，无需清理。")
        return True

    if in_scm:
        if dry:
            print(f"[dry] SCM 里仍有服务 {SERVICE}，会调用 DeleteService")
        else:
            good, msg = scm_delete()
            print(f"[{'+' if good else '!'}] SCM 删除 {SERVICE}: {msg}")
            ok = ok and good

    if info:
        image = str(info.get("ImagePath", ""))
        if "cps.sys" not in image.lower():
            print(f"[!] 服务 {SERVICE} 的 ImagePath 不含 cps.sys（{image!r}），**不动它**。")
        else:
            if dry:
                print(f"[dry] 会删除服务键 HKLM\\{SERVICE_KEY}  (ImagePath={image})")
            else:
                try:
                    _delete_tree(winreg.HKEY_LOCAL_MACHINE, SERVICE_KEY)
                    print(f"[+] 已删除服务键 {SERVICE}")
                except PermissionError as e:
                    # SCM 可能还拿着键；退化为标记删除
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICE_KEY, 0,
                                            winreg.KEY_SET_VALUE) as k:
                            winreg.SetValueEx(k, "Start", 0, winreg.REG_DWORD, 4)
                            winreg.SetValueEx(k, "DeleteFlag", 0, winreg.REG_DWORD, 1)
                        print(f"[~] 直接删键被拒({e})，已标记 Start=4/DeleteFlag=1（重启后消失）")
                    except Exception as e2:
                        print(f"[!] 处置服务键失败: {e2}")
                        ok = False

    for p in files:
        if dry:
            print(f"[dry] 会删除驱动文件 {p}")
        else:
            try:
                os.remove(p)
                print(f"[+] 已删除驱动文件 {p}")
            except OSError as e:
                print(f"[!] 删除 {p} 失败: {e}")
                ok = False
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    return 0 if clean(dry=args.dry_run) else 1


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    raise SystemExit(main())
