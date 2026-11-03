"""Native aiming basis and selected muzzle resource contract, without rendering."""
import csv
import io
import math
import re
import struct
import unittest
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP
import test_projectile_presentation_native as projectile_native
import hangar_experiment

ROOT = projectile_native.ROOT
ASSETS = ROOT / 'GundamOnline_CHINA_已解密/decrypted'


def blocks(text):
    """Immediate VRA blocks only; braces inside strings are not structural."""
    depth = 0
    for token in re.finditer(r'"(?:\\.|[^"\\])*"|[{}]', text):
        if token[0] == '{':
            if depth == 0:
                start = token.start()
            depth += 1
        elif token[0] == '}':
            depth -= 1
            if depth == 0:
                block = text[start:token.end()]
                name = re.match(r'\{(\w+)', block)[1]
                yield name, block[block.index(name)+len(name):-1]


class MuzzleEffectNativeTest(unittest.TestCase):
    def effects(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        for row in rows:
            if row[30] == 'GUN_SINGLE':
                yield row[0], (ASSETS/'fx'/row[42]).read_bytes().decode('cp932', errors='replace')

    def test_muzzle_is_a_short_pink_flash(self):
        # PT_01_100_01 was visually inspected: white core, pink halo.
        # Assert the selected resource actually uses it, rather than tinting
        # an unrelated blue thruster and calling that a pink muzzle flash.
        for item, text in self.effects():
            with self.subTest(item=item):
                self.assertIn('"fx/image/PT_01_100_01.png"', text)
                header = next(b for name, b in blocks(text) if name == 'Header')
                self.assertRegex(header, r'\(loop int8\[1\] 0\)')
                self.assertLessEqual(int(re.search(r'\(frame int16\[1\] (\d+)', header)[1]), 20)

    def test_muzzle_has_no_outer_pitch_over_the_native_aim_basis(self):
        for item, text in self.effects():
            with self.subTest(item=item):
                plug = next(b for name, b in blocks(text) if name == 'Plug')
                for name, work in blocks(plug):
                    if name != 'Work':
                        continue
                    for kind, rotation in blocks(work):
                        if kind == 'Rot':
                            values = re.search(r'\(rot vector3\[\d+\]\s*([^)]*)', rotation)
                            if values:
                                self.assertTrue(all(float(n) == 0 for n in
                                                    re.findall(r'-?\d+\.\d+', values[1])),
                                                'outer quarter-turn redirects the native aiming basis')

    def test_native_basis_forward_follows_horizontal_and_pitched_targets(self):
        for direction in ((0, 0, 1), (1, 0, 0), (0.6, 0.8, 0), (0, -0.6, 0.8)):
            with self.subTest(direction=direction):
                u = projectile_native.ProjectilePresentationNativeTest().machine()
                stack, target, stop, output = 0x20008000, 0x20001000, 0x20009000, 0x20002000
                u.mem_write(target, struct.pack('<3f', *direction))
                u.mem_write(stack, struct.pack('<4I', stop, output, target, 0x1089d54))
                captured = []

                def matrix(m, address, size, data):
                    if address == 0xb31400:
                        sp = m.reg_read(UC_X86_REG_ESP)
                        pointer = struct.unpack('<I', m.mem_read(sp+8, 4))[0]
                        captured.append(struct.unpack('<3f', m.mem_read(pointer+32, 12)))
                        m.emu_stop()

                u.hook_add(UC_HOOK_CODE, matrix)
                u.emu_start(0xb324b0, stop, count=2000)
                self.assertEqual(len(captured), 1)
                for actual, expected in zip(captured[0], direction):
                    self.assertTrue(math.isfinite(actual))
                    self.assertAlmostEqual(actual, expected, places=5)


if __name__ == '__main__':
    unittest.main()
