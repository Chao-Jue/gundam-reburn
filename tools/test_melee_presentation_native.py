"""Execute CAtkParamTable scalar mapping, excluding strings/effects/rendering."""
import csv
import io
import struct
import sys
import unittest
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment


class MeleePresentationNativeTest(unittest.TestCase):
    def parse(self, row):
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0, 0x1000)
        u.mem_map(0x400000, (len(image)+4095)&~4095)
        u.mem_write(0x400000, image)
        u.mem_map(0x20000000, 0x10000)
        stack, output, stop, stub, scalar = 0x20008000, 0x20001000, 0x20009000, 0x2000a000, 0x2000b000
        u.mem_write(stack, struct.pack('<4I', stop, 0x20003000, 0, output))
        u.reg_write(UC_X86_REG_ESP, stack)

        def primitive(m, address, size, data):
            if address not in (0xb081e0, 0xb08260, 0xb082e0, 0x55bb80, 0x40ce60, 0x53dd00):
                return
            sp = m.reg_read(UC_X86_REG_ESP)
            ret = struct.unpack('<I', m.mem_read(sp, 4))[0]
            if address == 0x53dd00:
                self.assertEqual(row[17], '')  # no invented attack flags
                flags = struct.unpack('<I', m.mem_read(sp+8, 4))[0]
                m.mem_write(flags, bytes(4))
                m.reg_write(UC_X86_REG_EAX, 0)
            elif address == 0x40ce60:
                left, right, count = struct.unpack('<3I', m.mem_read(sp+4, 12))
                a, b = bytes(m.mem_read(left, count)), bytes(m.mem_read(right, count))
                m.reg_write(UC_X86_REG_EAX, 0 if a == b else (1 if a > b else 0xffffffff))
            elif address in (0xb081e0, 0xb08260):
                column = struct.unpack('<I', m.mem_read(sp+8, 4))[0]
                value = row[column] or '0'
                if address == 0xb08260:
                    m.mem_write(scalar, struct.pack('<f', float(value)))
                    m.mem_write(stub, b'\xd9\x05'+struct.pack('<I', scalar)+b'\xc3')
                    m.reg_write(UC_X86_REG_EIP, stub)
                    return
                m.reg_write(UC_X86_REG_EAX, int(value)&0xffffffff)
            else:
                # Empty string/effect helpers only; no resource substitutions.
                if address == 0xb082e0:
                    column = struct.unpack('<I', m.mem_read(sp+12, 4))[0]
                    self.assertEqual(row[column], '')
                else:
                    self.assertEqual(row[28], '')
                dest = struct.unpack('<I', m.mem_read(sp+4, 4))[0]
                m.mem_write(dest, bytes(28))
                m.mem_write(dest+0x18, struct.pack('<I', 7 if address == 0x55bb80 else 15))
                m.reg_write(UC_X86_REG_EAX, dest)
            m.reg_write(UC_X86_REG_ESP, sp+4)
            m.reg_write(UC_X86_REG_EIP, ret)

        u.hook_add(UC_HOOK_CODE, primitive)
        u.emu_start(0x53deb0, stop, count=100000)
        self.assertEqual(u.reg_read(UC_X86_REG_EIP), stop)
        return bytes(u.mem_read(output, 0xa4))

    def test_generated_actions_have_native_duration_and_base_motion(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables('item/wrestle.csv').decode())))[2:]
        self.assertEqual({int(r[0]) for r in rows}, {880001, 880002, 880011, 880012})
        for row in rows:
            with self.subTest(action=row[0]):
                native = self.parse(row)
                self.assertEqual(struct.unpack_from('<I', native)[0], int(row[0]))
                dash = int(row[0]) in (880011, 880012)
                self.assertAlmostEqual(struct.unpack_from('<f', native, 0x14)[0], .366 if dash else .5)
                self.assertEqual(struct.unpack_from('<I', native, 0x64)[0], 36 if dash else 30)
                self.assertEqual(struct.unpack_from('<I', native, 0x10)[0], 0,
                                 'col5 is not the float duration at +14')
