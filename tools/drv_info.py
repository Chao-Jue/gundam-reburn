"""对保护模块的内核驱动做静态分析（PE 结构 / 导入 / 签名 / IOCTL 分发）。

用法:
    python tools/drv_info.py server/CPS_extracted.sys
"""

from __future__ import annotations

import hashlib
import re
import struct
import sys
from pathlib import Path

import capstone
import pefile


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "server/CPS_extracted.sys")
    d = path.read_bytes()
    print(f"### {path}  size={len(d)}  md5={hashlib.md5(d).hexdigest()}")
    print(f"    sha256={hashlib.sha256(d).hexdigest()}")

    pe = pefile.PE(data=d, fast_load=False)
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    import datetime

    ts = fh.TimeDateStamp
    print(f"Machine       = {fh.Machine:#06x} ({'x64' if fh.Machine==0x8664 else 'x86' if fh.Machine==0x14c else '?'})")
    print(f"Characteristics={fh.Characteristics:#06x}")
    print(f"Subsystem     = {oh.Subsystem} (1=native/driver)")
    print(f"ImageBase     = {oh.ImageBase:#x}   SizeOfImage={oh.SizeOfImage:#x}")
    print(f"EntryPoint    = {oh.AddressOfEntryPoint:#x}  (RVA)")
    print(f"TimeDateStamp = {datetime.datetime.utcfromtimestamp(ts)}")
    print("Sections:")
    for s in pe.sections:
        print(f"   {s.Name.rstrip(bytes([0])).decode('latin1'):10} VA={s.VirtualAddress:#08x} "
              f"VSz={s.Misc_VirtualSize:#08x} Raw={s.PointerToRawData:#08x} RSz={s.SizeOfRawData:#08x}")

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        print("Imports:")
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            names = [i.name.decode() if i.name else f"ord{i.ordinal}" for i in e.imports]
            print(f"   {e.dll.decode()}: {', '.join(names)}")
    else:
        print("Imports: <none>")

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        print("Exports:", [s.name.decode() for s in pe.DIRECTORY_ENTRY_EXPORT.symbols][:20])

    # ---- 字符串 ----
    strs = re.findall(rb"[\x20-\x7e]{5,}", d)
    wanted = []
    for s in strs:
        t = s.decode("latin1")
        low = t.lower()
        if any(k in low for k in ("device", "dosdevices", "symbolic", "driverentry", "\\systemroot",
                                  "cps", "xgg", "dlib", "protect", "version", "ntoskrnl", "\\\\??")):
            wanted.append(t)
    print("Strings(节选):")
    for t in dict.fromkeys(wanted):
        print("   ", t[:110])
    if not wanted:
        print("    <无>")

    # ---- 反汇编 DriverEntry 与 IOCTL 常量 ----
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if fh.Machine == 0x8664 else capstone.CS_MODE_32)
    md.detail = False
    img = pe.get_memory_mapped_image()

    ep_rva = oh.AddressOfEntryPoint
    print(f"\n--- DriverEntry 反汇编 (RVA {ep_rva:#x}) ---")
    n = 0
    for ins in md.disasm(img[ep_rva : ep_rva + 0x200], oh.ImageBase + ep_rva):
        print(f"   {ins.address:#012x}  {ins.mnemonic:8} {ins.op_str}")
        n += 1
        if n > 45:
            break
    if n == 0:
        print("   <取不到指令：入口落在 VMProtect 虚拟化节内>")

    ioctls = [0x222059, 0x222019, 0x22207C]
    print("\n--- 搜索 IOCTL 常量 ---")
    for io in ioctls:
        pats = [struct.pack("<I", io), struct.pack("<i", io)]
        for pat in pats:
            idx = 0
            while True:
                idx = d.find(pat, idx)
                if idx < 0:
                    break
                # 反推 RVA
                rva = None
                for s in pe.sections:
                    if s.PointerToRawData <= idx < s.PointerToRawData + s.SizeOfRawData:
                        rva = s.VirtualAddress + (idx - s.PointerToRawData)
                        break
                print(f"    {io:#x} 出现于 file {idx:#x}  rva {('0x%x' % rva) if rva else '?'}")
                idx += 1
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    raise SystemExit(main())
