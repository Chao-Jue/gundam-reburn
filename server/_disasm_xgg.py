"""Disassemble the exe call sites that lead into the XGG error dialog."""

from pathlib import Path

import capstone
import pefile

EXE = list(Path(r"D:\project\gundam-reburn\launcher\gundam").rglob("GundamOnline_CHINA.exe"))[0]
OUT = Path(r"D:\project\gundam-reburn\server\os_disasm.txt")
BASE = 0x400000
SITES = [0xDF64EE, 0x10B002E, 0x983540, 0x98EB16]


def main() -> None:
    pe = pefile.PE(str(EXE))
    data = EXE.read_bytes()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False
    lines = []
    for va in SITES:
        rva = va - BASE
        try:
            off = pe.get_offset_from_rva(rva)
        except Exception as exc:
            lines.append(f"{va:#x} no offset {exc}")
            continue
        start = max(0, off - 0x40)
        blob = data[start : off + 0x30]
        lines.append(f"--- va {va:#x} file {off:#x} ---")
        for insn in md.disasm(blob, BASE + rva - (off - start)):
            mark = " <" if insn.address == va else ""
            lines.append(f"{insn.address:#x} {insn.bytes.hex():24} {insn.mnemonic} {insn.op_str}{mark}")
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("wrote", len(lines))


if __name__ == "__main__":
    main()
