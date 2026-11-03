"""Native projectile count gate and flight time; no renderer or live writes."""
import csv
import io
import json
import math
import re
import struct
import sys
import unittest
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_ESI,
                              UC_X86_REG_EDI, UC_X86_REG_EIP, UC_X86_REG_EAX, UC_X86_REG_EBP)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment
import test_weapon_effect_native as effects_native


class ProjectilePresentationNativeTest(unittest.TestCase):
    def machine(self):
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0, 0x1000)
        u.mem_map(0x400000, (len(image)+4095)&~4095)
        u.mem_write(0x400000, image)
        u.mem_map(0x20000000, 0x10000)
        u.reg_write(UC_X86_REG_ESP, 0x20008000)
        return u

    def count_gate(self, count):
        u = self.machine()
        definition = 0x20001000
        u.reg_write(UC_X86_REG_ESI, definition)

        def external(m, address, size, data):
            if address == 0x4f39e2:
                m.emu_stop()
            elif address == 0x476680:
                # Substitute protected integer decoding only. The actual
                # caller must read definition+7B0 and branch on that result.
                self.assertEqual(m.reg_read(UC_X86_REG_ECX), definition+0x7b0)
                sp = m.reg_read(UC_X86_REG_ESP)
                ret = struct.unpack('<I', m.mem_read(sp, 4))[0]
                m.reg_write(UC_X86_REG_EAX, count)
                m.reg_write(UC_X86_REG_ESP, sp+4)
                m.reg_write(UC_X86_REG_EIP, ret)

        u.hook_add(UC_HOOK_CODE, external)
        u.emu_start(0x4f34fd, 0x4f3530, count=100)
        return u.reg_read(UC_X86_REG_EIP) == 0x4f3530

    def test_native_count_zero_skips_spawn_and_positive_enters(self):
        self.assertFalse(self.count_gate(0))
        self.assertTrue(self.count_gate(1))

    def throw_count_gate(self, count):
        u = self.machine()
        definition = 0x20001000
        u.reg_write(UC_X86_REG_EBP, definition)
        def decode(m, address, size, data):
            if address != 0x476680:
                return
            self.assertEqual(m.reg_read(UC_X86_REG_ECX), definition+0x7b0)
            sp = m.reg_read(UC_X86_REG_ESP)
            ret = struct.unpack('<I', m.mem_read(sp, 4))[0]
            m.reg_write(UC_X86_REG_EAX, count)
            m.reg_write(UC_X86_REG_ESP, sp+4)
            m.reg_write(UC_X86_REG_EIP, ret)
        u.hook_add(UC_HOOK_CODE, decode)
        def stop(m, address, size, data):
            if address in (0x4d74da, 0x4d7ba0):
                m.emu_stop()
        u.hook_add(UC_HOOK_CODE, stop)
        u.emu_start(0x4d74ac, 0x4d7ba1, count=100)
        return u.reg_read(UC_X86_REG_EIP) == 0x4d74da

    def test_generated_grenades_enter_native_throw_and_request_loop(self):
        self.assertFalse(self.throw_count_gate(0))
        self.assertTrue(self.throw_count_gate(1))
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        for row in rows:
            if row[30] == 'HAND_THROW':
                with self.subTest(item=row[0]):
                    self.assertTrue(self.throw_count_gate(int(row[104] or 0)),
                                    'zero count skips local throw and 7C0C send')

    def test_generated_grenades_have_a_loadable_projectile_visual(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        assets = ROOT / 'GundamOnline_CHINA_已解密/decrypted'
        effects = effects_native.WeaponEffectNativeTest()
        for row in rows:
            if row[30] == 'HAND_THROW':
                with self.subTest(item=row[0]):
                    # 4ED990 calls 4ED190 for this visual; a null result
                    # at 4EDBDx aborts projectile initialization entirely.
                    self.assertTrue(row[46], 'missing flight visual aborts native projectile init')
                    self.assertGreater(float(row[47] or 0), 0)
                    path = assets / effects.effect_path(row[46])
                    self.assertTrue(path.is_file())
                    data = path.read_bytes()
                    self.assertIn(b'{Model', data)

    def test_grenade_visual_and_dependencies_are_in_running_client_archive(self):
        # Read-only fx.hed directory capture, not the newer decrypted tree.
        # The old candidate exists in that tree but the live VFS rejects it.
        inventory = json.loads((ROOT / 'server/reference/grenade_fx_availability.json').read_text())
        available = set(inventory['available'])
        self.assertTrue(set(inventory['unavailable']).isdisjoint(available))
        assets = ROOT / 'GundamOnline_CHINA_已解密/decrypted'
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        for row in rows:
            if row[30] != 'HAND_THROW':
                continue
            with self.subTest(item=row[0]):
                self.assertIn(row[46], available,
                              'decrypted reference file is absent from running client fx.hed')
                data = (assets / 'fx' / row[46]).read_bytes()
                references = re.findall(rb'\(file string\[1\] "([^"]+)"', data)
                for raw in references:
                    path = raw.decode('ascii').replace('\\', '/')
                    if path.startswith('fx/'):
                        self.assertIn(path[3:], available, 'missing flight visual dependency')
                # VRA geometry additionally loads the paired model/texture.
                for path in available:
                    self.assertTrue((assets / 'fx' / path).is_file(), path)

    def test_grenade_impact_has_an_archive_available_effect_and_scale(self):
        inventory = json.loads((ROOT / 'server/reference/grenade_fx_availability.json').read_text())
        available = set(inventory['available'])
        assets = ROOT / 'GundamOnline_CHINA_已解密/decrypted/fx'
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        for row in rows:
            if row[30] != 'HAND_THROW':
                continue
            with self.subTest(item=row[0]):
                # 55CB0B/55CB53: CSV48/49 -> +23C/+290;
                # normal 4F2520 impact loads that path/scale.
                self.assertTrue(row[48], 'normal hand-throw impact has no effect')
                self.assertGreater(float(row[49] or 0), 0)
                self.assertIn(row[48], available)
                data = (assets / row[48]).read_bytes()
                for ref in re.findall(rb'\(file string\[1\] "([^"]+)"', data):
                    path = ref.decode('ascii').replace('\\', '/')
                    if path.startswith('fx/'):
                        self.assertIn(path[3:], available)

    def test_native_hand_throw_impact_callback_routes_to_explosion_at_target(self):
        u = self.machine()
        u.mem_map(0x20010000, 0x10000)
        game, stack = 0x20002000, 0x20008000
        u.mem_write(0x1161f28, struct.pack('<I', game))
        u.mem_write(game+0x109dc, struct.pack('<I', 100))
        u.mem_write(0x116200c, struct.pack('<I', 0x20003000))
        # Decoded A55620 arguments: entity,item,grenade,launch,target,ent,
        # msec,impact,fx,slot. This is not the complete wire decoder.
        args = [1, 777103, 7, 105, 65520, 160, 105, 65520, 160, 0, 0, 1, 0, 0]
        u.mem_write(stack, struct.pack('<15I', 0x20009000, *args))
        captured = []

        def external(m, address, size, data):
            sp = m.reg_read(UC_X86_REG_ESP)
            if address == 0x49fdc0:
                ret, dst, entity = struct.unpack('<3I', m.mem_read(sp, 12))
                self.assertEqual(entity, 1)
                # Empty entity wrapper skips unrelated special weapon logic.
                m.mem_write(dst, struct.pack('<I', 0x1161f30))
                m.reg_write(UC_X86_REG_EAX, dst)
                m.reg_write(UC_X86_REG_ESP, sp+12)
                m.reg_write(UC_X86_REG_EIP, ret)
            elif address == 0x4f2520:
                values = struct.unpack('<7I', m.mem_read(sp, 28))
                captured.append((values[1:4], struct.unpack('<3f', m.mem_read(values[4], 12)), values[5:]))
                m.emu_stop()

        u.hook_add(UC_HOOK_CODE, external)
        u.emu_start(0xa55620, 0x20009000, count=1000)
        self.assertEqual(captured, [((1, 777103, 7), (10500., -1600., 16000.), (0, 0))])

    def test_grenade_native_initial_velocity_is_not_zero(self):
        bullets = {int(r[0]): r for r in list(csv.reader(io.StringIO(
            hangar_experiment.weapon_tables('item/bullet.csv').decode())))[2:]}
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        for row in rows:
            if row[30] != 'HAND_THROW':
                continue
            with self.subTest(item=row[0]):
                speed = float(bullets[int(row[68])][5] or 0)
                u = self.machine()
                sp, output, entry, value = 0x20008000, 0x20001000, 0x20009000, 0x20009100
                u.reg_write(UC_X86_REG_ESI, output)
                # 505BD0 loads bullet+0C (CSV5), scales by enhancements,
                # then 505DB1..505DE6 multiplies the direction by that speed.
                # Use neutral enhancements and a unit forward direction.
                for offset, v in ((0x1c, 0.), (0x2c, 0.), (0x20, 1.)):
                    u.mem_write(sp+offset, struct.pack('<f', v))
                u.mem_write(value, struct.pack('<f', speed))
                u.mem_write(entry, b'\xd9\x05'+struct.pack('<I', value)
                            +b'\xe9'+struct.pack('<i', 0x505db1-(entry+11)))
                u.emu_start(entry, 0x505de6, count=100)
                velocity = struct.unpack('<3f', u.mem_read(output+0xc, 12))
                self.assertTrue(all(math.isfinite(v) for v in velocity))
                self.assertGreater(sum(v*v for v in velocity), 0,
                                   'zero bullet speed leaves the thrown grenade stationary')

    def test_grenade_has_visible_curvature_at_local_presentation_speed(self):
        bullets = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/bullet.csv').decode())))[2:]
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        by_item = {int(r[0]): r for r in bullets}
        for row in rows:
            if row[30] != 'HAND_THROW':
                continue
            with self.subTest(item=row[0]):
                speed = float(by_item[int(row[68])][5])
                u = self.machine()
                ctrl, stack, entry, dt_addr = 0x20001000, 0x20008000, 0x20009000, 0x20009100
                u.reg_write(UC_X86_REG_ESI, ctrl)
                # Neutral enhancements; horizontal aim plus the live native
                # 10-degree upward sine term. Not a full constructor test.
                upward = speed * math.sin(math.radians(10))
                u.mem_write(ctrl+0xc, struct.pack('<3f', 0, upward, speed))
                u.mem_write(dt_addr, struct.pack('<f', 1/60))
                u.mem_write(entry, b'\xd9\x05'+struct.pack('<I', dt_addr)
                            +b'\xe9'+struct.pack('<i', 0x505f03-(entry+11)))
                y = z = 0.
                max_y = 0.
                for _ in range(90):
                    # Actual native gravity and semi-implicit displacement;
                    # stop before position query/collision/rendering.
                    u.emu_start(entry, 0x505f49, count=100)
                    y += struct.unpack('<f', u.mem_read(stack+0x44, 4))[0]
                    z += struct.unpack('<f', u.mem_read(stack+0x30, 4))[0]
                    max_y = max(max_y, y)
                sag = upward*1.5-y
                self.assertGreater(max_y, 0)
                self.assertLess(y, max_y, 'trajectory must descend after its apex')
                # Local presentation acceptance, not recovered original range:
                # travel <=35m in1.5s and gravity deviation >=20% of travel.
                self.assertLessEqual(z, 3500, 'temporary 8000 speed looks like a straight shot')
                self.assertGreaterEqual(sag/z, .2, 'gravity curvature is too small relative to travel')

    def test_count_csv_column104_reaches_protected_field7b0(self):
        u = self.machine()
        definition = 0x20001000
        u.reg_write(UC_X86_REG_ESI, definition)
        u.reg_write(UC_X86_REG_EDI, 0x20003000)
        captured = []

        def primitives(m, address, size, data):
            if address not in (0xb081e0, 0x54bae0):
                return
            sp = m.reg_read(UC_X86_REG_ESP)
            ret, arg = struct.unpack('<2I', m.mem_read(sp, 8))
            if address == 0xb081e0:
                self.assertEqual(struct.unpack('<I', m.mem_read(sp+8, 4))[0], 104)
                m.reg_write(UC_X86_REG_EAX, 3)
                pop = 4
            else:
                captured.append((m.reg_read(UC_X86_REG_ECX)-definition,
                                 struct.unpack('<I', m.mem_read(arg, 4))[0]))
                pop = 8
            m.reg_write(UC_X86_REG_ESP, sp+pop)
            m.reg_write(UC_X86_REG_EIP, ret)

        u.hook_add(UC_HOOK_CODE, primitives)
        u.emu_start(0x55d312, 0x55d339, count=100)
        self.assertEqual(captured, [(0x7b0, 3)])

    def test_generated_guns_enter_spawn_and_have_visible_fx_and_speed(self):
        def rows(name):
            return list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(name).decode())))[2:]
        bullets = {int(r[0]): r for r in rows('item/bullet.csv')}
        assets = ROOT / 'GundamOnline_CHINA_已解密/decrypted'
        effects = effects_native.WeaponEffectNativeTest()
        for row in rows('item/weapon_settings.csv'):
            if row[30] != 'GUN_SINGLE':
                continue
            with self.subTest(item=row[0]):
                self.assertTrue(self.count_gate(int(row[104] or 0)), 'zero count skips whole spawn loop')
                self.assertGreater(int(row[103] or 0), 0, 'zero ammunition cost is not a shot prototype')
                for field, scale in ((42, 43), (46, 47)):
                    self.assertTrue(row[field], 'missing muzzle/projectile FX')
                    self.assertGreater(float(row[scale] or 0), 0)
                    self.assertTrue((assets / effects.effect_path(row[field])).is_file())
                speed = float(bullets[int(row[68])][5] or 0)
                self.assertGreater(speed, 0, 'native flight-time formula divides by speed')
                # Execute the actual x87 distance/speed consumer. Store its
                # floating return value with a tiny local fstp wrapper.
                u = self.machine()
                definition, returned, output = 0x20001000, 0x20009000, 0x20009100
                u.mem_write(definition+0xc, struct.pack('<f', speed))
                u.mem_write(0x20008000, struct.pack('<If', returned, 30000))
                u.mem_write(returned, b'\xd9\x1d'+struct.pack('<I', output))
                u.reg_write(UC_X86_REG_ECX, definition)
                u.emu_start(0x53f110, returned+6, count=100)
                duration = struct.unpack('<f', u.mem_read(output, 4))[0]
                self.assertTrue(math.isfinite(duration))
                self.assertAlmostEqual(duration, 30000/speed, places=5)


if __name__ == '__main__':
    unittest.main()
