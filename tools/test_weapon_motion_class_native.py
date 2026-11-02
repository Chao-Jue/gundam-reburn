"""Real motion-class enum rejects blank CSV tokens as FFFFFFFF."""
import csv
import io
import struct
import sys
import unittest
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX, UC_X86_REG_ESI

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment


class MotionClassNativeTest(unittest.TestCase):
    def native_layer(self, csv_value):
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000, (len(image)+4095)&~4095)
        u.mem_write(0x400000, image)
        u.mem_map(0x20000000, 0x10000)
        u.reg_write(UC_X86_REG_ESI, 0x20001000)
        u.reg_write(UC_X86_REG_ESP, 0x20008000)
        u.reg_write(UC_X86_REG_EAX, csv_value & 0xffffffff)
        # Actual col14 scalar result -> add1 -> definition+30.
        u.emu_start(0x55c51a, 0x55c52d, count=20)
        return struct.unpack('<I', u.mem_read(0x20001030, 4))[0]

    def test_unrecovered_shield_animation_does_not_overwrite_weapon_layer(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        shield = next(r for r in rows if int(r[0]) == hangar_experiment.SHIELD_ITEM_ID)
        self.assertEqual(self.native_layer(int(shield[14] or 0)), 0,
                         '48E0E0 skips channel0; current shield overwrites weapon channel1')

    def resolve(self, token):
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0, 0x1000)
        u.mem_map(0x400000, (len(image)+4095)&~4095)
        u.mem_write(0x400000, image)
        u.mem_map(0x20000000, 0x10000)
        stack, stop = 0x20001000, 0x20002000
        raw = token.encode('ascii')
        self.assertLessEqual(len(raw), 15)
        # By-value 28B MSVC string: allocator word, buffer16, size, capacity.
        u.mem_write(stack, struct.pack('<II', stop, 0)+raw.ljust(16, b'\0')
                    +struct.pack('<II', len(raw), 15))
        u.reg_write(UC_X86_REG_ESP, stack)

        def compare(m, address, size, data):
            if address != 0x40ce60:
                return
            sp = m.reg_read(UC_X86_REG_ESP)
            ret, left, right, count = struct.unpack('<4I', m.mem_read(sp, 16))
            a, b = bytes(m.mem_read(left, count)), bytes(m.mem_read(right, count))
            m.reg_write(UC_X86_REG_EAX, 0 if a == b else (1 if a > b else 0xffffffff))
            m.reg_write(UC_X86_REG_ESP, sp+4)
            m.reg_write(UC_X86_REG_EIP, ret)

        u.hook_add(UC_HOOK_CODE, compare)
        u.emu_start(0x55b060, stop, count=10000)
        return u.reg_read(UC_X86_REG_EAX)

    def test_blank_is_invalid_and_native_common_is_zero(self):
        self.assertEqual(self.resolve(''), 0xffffffff)
        self.assertEqual(self.resolve('COMMON'), 0)
        self.assertEqual(self.resolve('WRESTLE'), 20)
        self.assertEqual(self.resolve('SHIELD'), 30)

    def test_generated_rows_have_valid_motion_class(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        for row in rows:
            with self.subTest(item=row[0]):
                self.assertNotEqual(self.resolve(row[15]), 0xffffffff)

    def test_ranged_aim_class_resolves_an_existing_gm_upper_body_motion(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        for row in rows:
            if row[30] != 'GUN_SINGLE':
                continue
            with self.subTest(item=row[0]):
                motion = self.resolve(row[15]) * 1000 + 101
                path = ROOT / ('GundamOnline_CHINA_已解密/decrypted/chara/01/01/anim/'
                               f'MSA_0101_{motion:05d}.mrb')
                self.assertTrue(path.is_file(), 'COMMON has no GM aimed gun pose101')

    def test_melee_has_a_linked_presentation_row_and_existing_motion(self):
        body = hangar_experiment.weapon_tables('item/wrestle.csv')
        self.assertIsNotNone(body, 'melee requests have no CAtkParamTable row')
        attacks = {int(r[0]): r for r in list(csv.reader(io.StringIO(body.decode())))[2:]}
        weapons = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        for row in weapons:
            if row[30] != 'WRESTLE':
                continue
            with self.subTest(item=row[0]):
                self.assertEqual(int(row[114] or 0), 1)
                action = attacks[int(row[70])]
                self.assertGreater(int(action[8]), 0)
                motion = self.resolve(row[15])*1000+int(action[27])
                self.assertTrue((ROOT / ('GundamOnline_CHINA_已解密/decrypted/chara/01/01/anim/'
                                        f'MSA_0101_{motion:05d}.mrb')).is_file())
