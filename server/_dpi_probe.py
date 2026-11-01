#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""验证「DPI 缩放导致 GetSystemMetrics 与真实显示模式不一致」的假设。

背景：游戏的 RVA 0x58f18d 处把配置对象里的要求分辨率（实测 1920x1080）
      和 GetSystemMetrics(0/1)（实测 1536x864）比较，1536 < 1920 → 弹框。
      1920/1.25 = 1536、1080/1.25 = 864 —— 高度怀疑本机桌面是 1920x1080
      且缩放 125%，而进程非 DPI 感知所以拿到虚拟值。

本脚本对比：
  A. GetSystemMetrics(0/1)              —— 进程 DPI 感知模式决定（虚拟值）
  B. EnumDisplaySettings(ENUM_CURRENT)  —— 永远是物理像素
  C. GetDeviceCaps(HORZRES/VERTRES)     —— 同 A，受 DPI 虚拟化影响
  D. GetDpiForSystem / 注册表 LogPixels —— 缩放比例
  E. SetProcessDPIAware() 之后再测 A     —— 验证"变成 DPI 感知后 A==B"
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import sys

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32


class DEVMODEW(ctypes.Structure):
    _fields_ = [
        ("dmDeviceName", wt.WCHAR * 32),
        ("dmSpecVersion", wt.WORD), ("dmDriverVersion", wt.WORD),
        ("dmSize", wt.WORD), ("dmDriverExtra", wt.WORD),
        ("dmFields", wt.DWORD),
        ("dmOrientation", ctypes.c_short), ("dmPaperSize", ctypes.c_short),
        ("dmPaperLength", ctypes.c_short), ("dmPaperWidth", ctypes.c_short),
        ("dmScale", ctypes.c_short), ("dmCopies", ctypes.c_short),
        ("dmDefaultSource", ctypes.c_short), ("dmPrintQuality", ctypes.c_short),
        ("dmColor", ctypes.c_short), ("dmDuplex", ctypes.c_short),
        ("dmYResolution", ctypes.c_short), ("dmTTOption", ctypes.c_short),
        ("dmCollate", ctypes.c_short), ("dmFormName", wt.WCHAR * 32),
        ("dmLogPixels", wt.WORD), ("dmBitsPerPel", wt.DWORD),
        ("dmPelsWidth", wt.DWORD), ("dmPelsHeight", wt.DWORD),
        ("dmDisplayFlags", wt.DWORD), ("dmDisplayFrequency", wt.DWORD),
        ("dmICMMethod", wt.DWORD), ("dmICMIntent", wt.DWORD),
        ("dmMediaType", wt.DWORD), ("dmDitherType", wt.DWORD),
        ("dmReserved1", wt.DWORD), ("dmReserved2", wt.DWORD),
        ("dmPanningWidth", wt.DWORD), ("dmPanningHeight", wt.DWORD),
    ]


def metrics() -> tuple[int, int]:
    return user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)


def device_caps() -> tuple[int, int]:
    hdc = user32.GetDC(0)
    try:
        return gdi32.GetDeviceCaps(hdc, 8), gdi32.GetDeviceCaps(hdc, 10)  # HORZRES/VERTRES
    finally:
        user32.ReleaseDC(0, hdc)


def display_mode() -> tuple[int, int, int, int] | None:
    dm = DEVMODEW()
    dm.dmSize = ctypes.sizeof(DEVMODEW)
    if not user32.EnumDisplaySettingsW(None, -1, ctypes.byref(dm)):   # ENUM_CURRENT_SETTINGS
        return None
    return dm.dmPelsWidth, dm.dmPelsHeight, dm.dmDisplayFrequency, dm.dmBitsPerPel


def system_dpi() -> int | None:
    try:
        f = user32.GetDpiForSystem
        f.restype = ctypes.c_uint
        return f()
    except AttributeError:
        return None


def logpixels() -> int | None:
    try:
        v = ctypes.c_int()
        n = wt.DWORD(4)
        # HKEY_CURRENT_USER = 0x80000001
        r = ctypes.windll.advapi32.RegGetValueW(
            ctypes.c_void_p(0x80000001),
            "Control Panel\\Desktop", "LogPixels", 0x00000010, None,
            ctypes.byref(v), ctypes.byref(n))
        return v.value if r == 0 else None
    except Exception:
        return None


def is_aware() -> dict:
    # 0x1000 = DPI_AWARENESS_CONTEXT_UNAWARE, 0x2000 = SYSTEM_AWARE, 0x4000 = PER_MONITOR
    out = {}
    for name, val in (("unaware", 0), ("system", 1), ("perMonitor", 2)):
        try:
            out[name] = user32.IsProcessDPIAware() if val == 0 else None
        except Exception:
            out[name] = None
    try:
        f = user32.GetThreadDpiAwarenessContext
        f.restype = ctypes.c_void_p
        out["ctxRaw"] = hex(f() or 0)
    except Exception:
        out["ctxRaw"] = None
    return out


def main() -> int:
    print("=" * 70)
    print("DPI / 显示模式 对照")
    print("=" * 70)
    m0, m1 = metrics()
    print(f"[A] GetSystemMetrics(0/1)                 = {m0} x {m1}")
    dm = display_mode()
    if dm:
        print(f"[B] EnumDisplaySettings(ENUM_CURRENT)     = {dm[0]} x {dm[1]}  @{dm[2]}Hz {dm[3]}bpp")
    else:
        print("[B] EnumDisplaySettings 失败")
    c0, c1 = device_caps()
    print(f"[C] GetDeviceCaps(HORZRES/VERTRES)        = {c0} x {c1}")
    print(f"[D] GetDpiForSystem                       = {system_dpi() or 'n/a'}")
    lp = logpixels()
    print(f"[D] HKCU Control Panel\\Desktop\\LogPixels  = {lp if lp is not None else 'n/a'}"
          f"{'  (≈%d%% 缩放)' % round((lp or 96) / 96 * 100) if lp else ''}")
    print(f"[E] IsProcessDPIAware()                   = {user32.IsProcessDPIAware()}")
    print(f"[E] DpiAwarenessContext                   = {is_aware().get('ctxRaw')}")

    print("-" * 70)
    if dm and (m0, m1) != (dm[0], dm[1]):
        ratio = dm[0] / m0 if m0 else 0
        print(f"[!] 不一致：物理 {dm[0]}x{dm[1]}，进程看到 {m0}x{m1}（比值 {ratio:.4f}）")
        if abs(ratio - 1.25) < 0.02:
            print("[!] 比值 ≈ 1.25 → 高度符合「125% 缩放 + 非 DPI 感知进程」")
        elif abs(ratio - 1.5) < 0.02:
            print("[!] 比值 ≈ 1.50 → 符合「150% 缩放」")
        elif abs(ratio - 1.75) < 0.02:
            print("[!] 比值 ≈ 1.75")
        elif abs(ratio - 2.0) < 0.02:
            print("[!] 比值 ≈ 2.00 → 符合「200% 缩放」")
        print(f"[!] 游戏要 1920x1080 而只看到 {m0}x{m1} → "
              f"{'会被判为分辨率不足' if m0 < 1920 or m1 < 1080 else '刚好够'}")
    else:
        print("[=] 一致（或拿不到），DPI 假设不成立")

    print("-" * 70)
    print("[*] 尝试 SetProcessDPIAware() 后再测 A：")
    try:
        user32.SetProcessDPIAware()
        m0b, m1b = metrics()
        print(f"    变成 DPI 感知后 GetSystemMetrics = {m0b} x {m1b}")
        if dm and (m0b, m1b) == (dm[0], dm[1]):
            print("    [OK] 与物理分辨率一致 -> 说明关掉缩放/改 DPI 感知即可解决")
    except Exception as e:  # noqa: BLE001
        print(f"    失败: {e}")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    raise SystemExit(main())
