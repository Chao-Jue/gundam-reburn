"""Execute the real weapon icon dispatcher; substitute the texture loader only."""
import csv
import io
from pathlib import Path
import struct
import sys
import unittest
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EIP

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment as experiment


class WeaponIconsNativeTest(unittest.TestCase):
    def test_weapon_icons_reach_large_and_small_texture_loaders(self):
        rows = list(csv.reader(io.StringIO(experiment.table_body(
            'item/weapon_settings.csv').decode())))[2:]
        expected = {777101: 2010501, 777102: 4010101, 777103: 10020101}
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        for row in rows:
            if int(row[0]) not in expected:
                continue
            for large in (0, 1):
                with self.subTest(item=row[0], large=large):
                    u = Uc(UC_ARCH_X86, UC_MODE_32)
                    u.mem_map(0x400000, (len(image) + 4095) & ~4095)
                    u.mem_write(0x400000, image)
                    u.mem_map(0x20000000, 0x20000)
                    item, weapon, sp, end = 0x20001000, 0x20002000, 0x20010000, 0x20018000
                    # 0x558560 category WEAPON=1; 0x55C45D stores col2 at weapon+4.
                    u.mem_write(item + 0x40, struct.pack('<I', 1))
                    u.mem_write(item + 0x4c, struct.pack('<I', weapon))
                    u.mem_write(weapon + 4, struct.pack('<I', int(row[2] or 0)))
                    u.mem_write(sp, struct.pack('<II', end, large))
                    u.reg_write(UC_X86_REG_ESP, sp)
                    u.reg_write(UC_X86_REG_ECX, item)
                    seen = []

                    def capture(m, address, size, data):
                        if address in (0xa317f0, 0xa318f0):
                            p = m.reg_read(UC_X86_REG_ESP)
                            _, icon, fallback = struct.unpack('<III', m.mem_read(p, 12))
                            seen.append((address, icon, fallback))
                            m.reg_write(UC_X86_REG_EIP, end)

                    u.hook_add(UC_HOOK_CODE, capture)
                    u.emu_start(0x558110, end, count=200)
                    self.assertEqual(seen, [(0xa317f0 if large else 0xa318f0,
                                             expected[int(row[0])], 0)])


if __name__ == '__main__':
    unittest.main()
