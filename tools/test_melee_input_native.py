"""Execute the current client's normal/boost melee base selection block."""
import csv
import io
import struct
import sys
import unittest
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import (UC_X86_REG_ESP, UC_X86_REG_ESI,
                              UC_X86_REG_EDI, UC_X86_REG_EAX)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment


class MeleeInputNativeTest(unittest.TestCase):
    def choose(self, row, boost):
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000, (len(image)+4095)&~4095)
        u.mem_write(0x400000, image)
        u.mem_map(0x20000000, 0x10000)
        move, definition, vt, predicate = 0x20001000, 0x20003000, 0x20005000, 0x20006000
        u.mem_write(move, struct.pack('<I', vt))
        for offset in (0xa8, 0x70):
            u.mem_write(vt+offset, struct.pack('<I', predicate))
        u.mem_write(predicate, b'\xb8'+struct.pack('<I', int(boost))+b'\xc3')
        u.mem_write(definition+0x734, struct.pack('<2I', int(row[69] or 0), int(row[70] or 0)))
        u.reg_write(UC_X86_REG_ESP, 0x20008000)
        u.reg_write(UC_X86_REG_ESI, move)
        u.reg_write(UC_X86_REG_EDI, definition)
        u.emu_start(0x4bcb94, 0x4bcbc1, count=100)
        return u.reg_read(UC_X86_REG_EAX)

    def test_generated_sabers_have_distinct_normal_and_boost_presentations(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        attacks = {int(r[0]): r for r in list(csv.reader(io.StringIO(
            hangar_experiment.weapon_tables('item/wrestle.csv').decode())))[2:]}
        for row in rows:
            if row[30] != 'WRESTLE':
                continue
            with self.subTest(item=row[0]):
                normal, boost = self.choose(row, False), self.choose(row, True)
                self.assertNotEqual(normal, 0, 'basic clicks currently select missing base0')
                self.assertNotEqual(normal, boost)
                self.assertEqual(int(row[113]), 1)
                self.assertEqual(int(row[114]), 1)
                self.assertNotEqual(attacks[normal][27], attacks[boost][27])


if __name__ == '__main__':
    unittest.main()
