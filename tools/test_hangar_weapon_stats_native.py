"""CSV scalar parser plus actual x87 panel conversions (no live client)."""
import csv
import io
from pathlib import Path
import struct
import sys
import unittest
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment as experiment


class WeaponStatsNativeTest(unittest.TestCase):
    def test_projectile_radius_and_attribute_visibility(self):
        def rows(name):
            return list(csv.reader(io.StringIO(experiment.table_body(name).decode())))[2:]
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        builds = {int(r[0]): r for r in rows('develop/buildup_weapon.csv')}
        bullets = {int(r[0]): r for r in rows('item/bullet.csv')}
        for item, mask in ((777101, 0x203b), (777102, 0x21), (777103, 0x2111)):
            u = Uc(UC_ARCH_X86, UC_MODE_32)
            u.mem_map(0x400000, (len(image) + 4095) & ~4095)
            u.mem_write(0x400000, image)
            u.mem_map(0x20000000, 0x20000)
            weapon, build, node, bullet, sp, end = [0x20001000+i*0x1000 for i in range(6)]
            u.mem_write(0x1169560, struct.pack('<I', build))
            u.mem_write(weapon+0x970, struct.pack('<II', bullet, 1 if item in bullets else 0))
            u.mem_write(weapon+0x44, struct.pack('<I', 10 if item == 777103 else 1))
            u.mem_write(node+0x14, bytes(int(v) != 0 for v in builds[item][1:11]))
            u.mem_write(sp, struct.pack('<II', end, weapon))
            u.reg_write(UC_X86_REG_ESP, sp)

            def lookup(m, a, size, data):
                if a != 0x49f450:
                    return
                p = m.reg_read(UC_X86_REG_ESP)
                ret, out = struct.unpack('<II', m.mem_read(p, 8))
                m.mem_write(out, struct.pack('<I', node))
                m.reg_write(UC_X86_REG_ESP, p+12)
                m.reg_write(UC_X86_REG_EIP, ret)

            u.hook_add(UC_HOOK_CODE, lookup)
            u.emu_start(0x7a2810, end, count=500)
            self.assertEqual(u.reg_read(UC_X86_REG_EAX), mask, item)
            if item == 777103:
                u.mem_write(sp+0x14, struct.pack('<f', float(bullets[item][11])))
                u.reg_write(UC_X86_REG_ESP, sp)
                u.emu_start(0x7a39d1, 0xc12e30, count=50)
                capture = end+0x100
                u.mem_write(capture, b'\xd9\x1d'+struct.pack('<I', bullet))
                u.emu_start(capture, capture+6, count=1)
                self.assertEqual(int(struct.unpack('<f', u.mem_read(bullet, 4))[0]), 5000)

    def test_range_and_reload_templates_produce_wiki_panel_values(self):
        def rows(name):
            return list(csv.reader(io.StringIO(experiment.table_body(name).decode())))[2:]
        settings = {int(r[0]): r for r in rows('item/weapon_settings.csv')}
        details = {(r[0], r[1]): r for r in rows('item/weapon_battle_detail.csv')}
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        cases = [(777101, 'RANGE', 77, 0x55a630, 0x7a3351, 300),
                 (777101, 'RELOAD', 88, 0x55a690, 0x7a34a1, 680),
                 (777103, 'RELOAD', 88, 0x55a690, 0x7a34a1, 760),
                 (777101, 'STABILITY', 81, 0x55a650, 0x7a3091, 800),
                 (777101, 'LOCKON_CAM', 90, 0x55a6b0, 0x7a3601, 780),
                 (777102, 'LOCKON_CAM', 90, 0x55a6b0, 0x7a3601, 740)]
        for item, kind, col, parser, panel, expected in cases:
            with self.subTest(item=item, kind=kind):
                row = details.get((kind, settings[item][col]))
                self.assertIsNotNone(row, 'missing linked performance template')
                u = Uc(UC_ARCH_X86, UC_MODE_32)
                u.mem_map(0x400000, (len(image) + 4095) & ~4095)
                u.mem_write(0x400000, image)
                u.mem_map(0x20000000, 0x20000)
                sp, scalar, output, stub, end = 0x20010000, 0x20001000, 0x20002000, 0x20003000, 0x20018000
                u.mem_write(scalar, struct.pack('<f', float(row[2])))
                # Substitute only CSV float accessor, leaving native scale/store intact.
                u.mem_write(stub, b'\xd9\x05' + struct.pack('<I', scalar) + b'\xc3')
                u.mem_write(sp, struct.pack('<III', end, 0, output))
                u.reg_write(UC_X86_REG_ESP, sp)

                def hook(m, a, size, data):
                    if a == 0xb08260:
                        m.reg_write(UC_X86_REG_EIP, stub)

                u.hook_add(UC_HOOK_CODE, hook)
                u.emu_start(parser, end, count=200)
                value = bytes(u.mem_read(output, 4))
                u.mem_write(sp + 0x14, value)
                u.reg_write(UC_X86_REG_ESP, sp)
                # Stop before integer conversion; capture its real x87 input.
                u.emu_start(panel, 0xc12e30, count=100)
                capture = stub + 0x100
                u.mem_write(capture, b'\xd9\x1d' + struct.pack('<I', output))
                u.emu_start(capture, capture + 6, count=1)
                self.assertEqual(int(struct.unpack('<f', u.mem_read(output, 4))[0]), expected)


if __name__ == '__main__':
    unittest.main()
