#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""环境自检：一眼看出「hypervisor 关掉了没」以及「到底重启了没」。

用法：
    python tools/env_check.py

判据（三件事必须同时成立，才说明改动生效了）：
    1. CPUID.1:ECX bit31 == 0       —— hypervisor 不再对用户态暴露
                                       （Themida 的反虚拟机检查读的就是它）
    2. 系统连续运行时长 < 10 分钟    —— 确实重启过
                                       （快速启动 / 休眠恢复不会重置这个计时器）
    3. SystemStartOptions 里是 HYPERVISORLAUNCHTYPE=OFF
                                       （它只反映**当前这次**启动实际用的选项）
"""
from __future__ import annotations

import datetime
import os
import sys
import winreg

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cpuid_probe import make_cpuid  # noqa: E402

OK = "[OK]  "
BAD = "[!!]  "
INFO = "[--]  "


def uptime() -> datetime.timedelta:
    """GetTickCount64：真正的重启会清零；快速启动/休眠恢复不会。"""
    import ctypes

    ms = ctypes.windll.kernel32.GetTickCount64()
    return datetime.timedelta(milliseconds=ms)


def read_boot_options() -> str:
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Control") as k:
            return str(winreg.QueryValueEx(k, "SystemStartOptions")[0])
    except Exception as e:  # noqa: BLE001
        return f"<读取失败: {e}>"


def read_hiberboot() -> str:
    try:
        with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Power") as k:
            v = int(winreg.QueryValueEx(k, "HiberbootEnabled")[0])
            return f"{v}  ({'快速启动已启用' if v else '快速启动已关闭'})"
    except Exception as e:  # noqa: BLE001
        return f"<读取失败: {e}>"


def hypervisor_services() -> str:
    out = []
    for name in ("vmcompute", "HvHost", "hns", "vmms"):
        try:
            with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    rf"SYSTEM\CurrentControlSet\Services\{name}") as k:
                start = int(winreg.QueryValueEx(k, "Start")[0])
            tag = {0: "Boot", 1: "System", 2: "Auto", 3: "Manual", 4: "Disabled"}.get(start, str(start))
            out.append(f"{name}={tag}")
        except FileNotFoundError:
            pass
        except Exception:  # noqa: BLE001
            pass
    return ", ".join(out) if out else "(无)"


def main() -> int:
    if sys.platform != "win32":
        print("仅 Windows。", file=sys.stderr)
        return 2

    print("=" * 68)
    print(" gundam-reburn 环境自检")
    print("=" * 68)
    print(f"{INFO}时间        : {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f"{INFO}Python      : {sys.version.split()[0]}  {sys.maxsize > 2**32 and '64-bit' or '32-bit'}")

    cpuid = make_cpuid()
    _, _, ecx1, _ = cpuid(1)
    bit31 = (ecx1 >> 31) & 1
    max_leaf, b, c, d = cpuid(0)
    vendor = bytes(bytearray(b.to_bytes(4, "little") + d.to_bytes(4, "little")
                             + c.to_bytes(4, "little"))).decode("latin1")

    print()
    print(f"{INFO}CPU vendor  : {vendor!r}   (max leaf {max_leaf:#x})")
    print(f"{INFO}CPUID.1:ECX : 0x{ecx1:08x}")
    if max_leaf >= 0x40000000:
        _, hb, hc, hd = cpuid(0x40000000)
        try:
            hv_vendor = bytes(bytearray(hb.to_bytes(4, "little") + hc.to_bytes(4, "little")
                                        + hd.to_bytes(4, "little"))).decode("latin1")
        except Exception:  # noqa: BLE001
            hv_vendor = "?"
        print(f"{INFO}hypervisor  : {hv_vendor!r}")
    else:
        print(f"{INFO}hypervisor  : (厂商叶子 0x40000000 不可用)")

    if bit31:
        print(f"{BAD}CPUID.1:ECX bit31 = 1  ->  hypervisor 仍在对用户态暴露")
        print("      Themida 的反虚拟机检查会命中，游戏会弹")
        print("      'Sorry, this application cannot run under a Virtual Machine'。")
    else:
        print(f"{OK}CPUID.1:ECX bit31 = 0  ->  hypervisor 已隐藏，Themida 那一关应该能过")

    up = uptime()
    mins = up.total_seconds() / 60.0
    print()
    print(f"{INFO}真实开机时间: {datetime.datetime.now() - up:%Y-%m-%d %H:%M:%S}  (连续运行 {up})")
    if mins < 10:
        print(f"{OK}刚开机不久 -> 这次是**真重启**")
    else:
        print(f"{BAD}已连续运行 {up.days} 天 -> **没有发生真重启**")
        print("      休眠恢复 / 〔关机再开机〕都不会重置这个计时器，")
        print("      也不会按新的 BCD 重新初始化 hypervisor。")

    print()
    opts = read_boot_options()
    print(f"{INFO}本次启动选项: {opts}")
    flat = opts.upper().replace(" ", "")
    if "HYPERVISORLAUNCHTYPE=OFF" in flat:
        print(f"{OK}本次启动 hypervisor = OFF")
    elif "HYPERVISORLAUNCHTYPE" in flat:
        print(f"{BAD}本次启动 hypervisor 仍是 AUTO -> 当前这个会话就是带着 hypervisor 跑的")

    print()
    print(f"{INFO}快速启动    : {read_hiberboot()}")
    print(f"{INFO}虚拟化服务  : {hypervisor_services()}")
    print("      提示：HiberbootEnabled=1 时【关机再开机】会恢复上次的内核会话，")
    print("            所以要改 hypervisor 必须用【重启】，或者关掉快速启动。")

    print()
    print("-" * 68)
    if bit31 == 0:
        print("结论：环境已就绪。下一步 ->  python tools/plain_launch.py --seconds 40")
    else:
        print("结论：hypervisor 仍在。请以管理员执行 tools/fix_hypervisor_off.cmd，")
        print("      然后【重启】（不是关机再开机），再跑一次本脚本确认。")
        print("      完整背景与回滚步骤见 server/环境改动记录.md")
    print("-" * 68)
    return 0 if bit31 == 0 else 1


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass
    raise SystemExit(main())
