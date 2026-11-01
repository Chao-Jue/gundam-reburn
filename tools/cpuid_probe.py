"""读 CPUID，证明这台机器对用户态暴露了 hypervisor。

Themida / VMProtect 的反虚拟机检查读的就是 CPUID：
  - CPUID.1:ECX bit31 = 1  -> 存在 hypervisor
  - CPUID.40000000H        -> hypervisor 厂商标识：
                              "Microsoft Hv" = Hyper-V / VBS / VirtualMachinePlatform
                              "VMwareVMware" / "VBoxVBoxVBox" / "KVMKVMKVM"
Windows 只要启用了 Hyper-V 或 "虚拟机平台(VirtualMachinePlatform)" 或 VBS，
它自己就跑在 Hyper-V 根分区里，上面两项都会亮 —— 于是 Themida 拒绝启动。

实现说明：不依赖编译器。直接在可执行内存里写一小段 x64 机器码执行 cpuid
（CPUID 结果与 32/64 位无关）。

用法：python tools/cpuid_probe.py
"""

from __future__ import annotations

import ctypes
import struct
import sys

# push rbx; mov eax,ecx; mov ecx,edx; cpuid; mov [r8],eax; mov [r8+4],ebx;
# mov [r8+8],ecx; mov [r8+12],edx; pop rbx; ret
CODE = bytes([
    0x53,                               # push rbx
    0x89, 0xC8,                         # mov eax, ecx   (leaf)
    0x89, 0xD1,                         # mov ecx, edx   (subleaf)
    0x0F, 0xA2,                         # cpuid
    0x41, 0x89, 0x00,                   # mov [r8], eax
    0x41, 0x89, 0x58, 0x04,             # mov [r8+4], ebx
    0x41, 0x89, 0x48, 0x08,             # mov [r8+8], ecx
    0x41, 0x89, 0x50, 0x0C,             # mov [r8+12], edx
    0x5B,                               # pop rbx
    0xC3,                               # ret
])

PAGE_EXECUTE_READWRITE = 0x40


def make_cpuid():
    buf = ctypes.create_string_buffer(CODE, len(CODE))
    old = ctypes.c_ulong(0)
    ok = ctypes.windll.kernel32.VirtualProtect(
        ctypes.cast(buf, ctypes.c_void_p), len(CODE),
        PAGE_EXECUTE_READWRITE, ctypes.byref(old))
    if not ok:
        raise OSError("VirtualProtect 失败")
    proto = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.c_uint32,
                             ctypes.POINTER(ctypes.c_uint32))
    fn = proto(ctypes.addressof(buf))
    out = (ctypes.c_uint32 * 4)()

    def cpuid(leaf: int, sub: int = 0):
        fn(leaf, sub, out)
        return out[0], out[1], out[2], out[3]

    return cpuid


def main() -> int:
    if sys.platform != "win32":
        print("仅 Windows。", file=sys.stderr)
        return 2
    cpuid = make_cpuid()

    max_leaf, b, c, d = cpuid(0)
    vendor = struct.pack("<III", b, d, c).decode("latin1")
    print(f"CPU vendor          : {vendor!r}")
    print(f"CPUID max leaf      : {max_leaf:#010x}")

    _, _, ecx1, _ = cpuid(1)
    hv_bit = (ecx1 >> 31) & 1
    print(f"CPUID.1:ECX bit31   : {hv_bit}   <- 1 = 存在 hypervisor")

    if max_leaf >= 0x40000000:
        mx, b, c, d = cpuid(0x40000000)
        hv_vendor = struct.pack("<III", b, c, d).decode("latin1")
        print(f"hypervisor vendor   : {hv_vendor!r}   (max leaf {mx:#x})")
        e0, _, _, _ = cpuid(0x40000001)
        print(f"CPUID.40000001H EAX : {e0:#010x}")
    else:
        print("hypervisor vendor   : (不支持 0x40000000)")

    hv = (hv_bit == 1) or (max_leaf >= 0x40000000 and any(
        struct.pack("<III", b, c, d).strip(b"\x00")))
    print()
    if hv_bit == 1:
        print("结论：CPUID 明确报告“运行在 hypervisor 之下”。")
        print("      Themida 的反虚拟机检查会命中 -> 弹 'cannot run under a Virtual Machine'。")
        print("      要在物理机外观下运行，需要关掉 Hyper-V / VirtualMachinePlatform / VBS 并重启。")
    else:
        print("结论：没有 hypervisor 暴露，反虚拟机检查不应因 CPUID 命中。")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    raise SystemExit(main())
