"""Execute the actual client payload-column assignment block offline.

The CSV integer accessor is substituted; this does not exercise full CSV loading.
"""
import csv
import io
from pathlib import Path
import struct
import sys
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EAX

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment


class NativePayloadTest(unittest.TestCase):
    def test_native_column_assignment_reads_gm_payload(self):
        row = list(csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_settings.csv').decode())))[2]
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(0x400000, (len(image) + 4095) & ~4095)
        uc.mem_write(0x400000, image)
        uc.mem_map(0x20000000, 0x20000)
        uc.reg_write(UC_X86_REG_ESP, 0x20010000)
        uc.reg_write(UC_X86_REG_ESI, 0x20001000)
        uc.reg_write(UC_X86_REG_EDI, 0x20002000)
        seen = []

        def accessor(machine, address, size, data):
            if address != 0xB081E0:
                return
            sp = machine.reg_read(UC_X86_REG_ESP)
            ret, source, column = struct.unpack('<III', machine.mem_read(sp, 12))
            seen.append(column)
            machine.reg_write(UC_X86_REG_EAX, int(row[column]))
            machine.reg_write(UC_X86_REG_ESP, sp + 12)
            machine.reg_write(UC_X86_REG_EIP, ret)

        uc.hook_add(UC_HOOK_CODE, accessor)
        uc.emu_start(0x54F497, 0x54F4AE, count=30)
        self.assertEqual(seen, [52])
        self.assertEqual(struct.unpack('<I', uc.mem_read(0x200010E8, 4))[0], 1450)


if __name__ == '__main__':
    unittest.main()
