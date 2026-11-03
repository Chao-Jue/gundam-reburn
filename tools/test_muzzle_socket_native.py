"""Execute native CSV and muzzle socket-range setup; no live writes/rendering."""
import csv
import io
import struct
import unittest
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_ESP, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_ECX,
                              UC_X86_REG_EAX, UC_X86_REG_EIP)
import test_projectile_presentation_native as projectile_native
import hangar_experiment

ROOT = projectile_native.ROOT


class MuzzleSocketNativeTest(unittest.TestCase):
    def socket_range(self, row):
        u = projectile_native.ProjectilePresentationNativeTest().machine()
        definition, stack = 0x20001000, 0x20008000
        u.reg_write(UC_X86_REG_ESI, definition)
        u.reg_write(UC_X86_REG_EDI, 0x20003000)

        def csv_integer(m, address, size, data):
            if address != 0xb081e0:
                return
            sp = m.reg_read(UC_X86_REG_ESP)
            ret, source, column = struct.unpack('<3I', m.mem_read(sp, 12))
            self.assertIn(column, (7, 8))
            m.reg_write(UC_X86_REG_EAX, int(row[column] or 0))
            m.reg_write(UC_X86_REG_ESP, sp+4)
            m.reg_write(UC_X86_REG_EIP, ret)

        hook = u.hook_add(UC_HOOK_CODE, csv_integer)
        # CSV7/8 -> definition+18/+1C; stop before CSV9 is consumed.
        u.emu_start(0x55c473, 0x55c48f, count=50)
        u.hook_del(hook)
        u.reg_write(UC_X86_REG_ESP, stack)
        # Actual 49B180 setup: a zero end means a single start socket,
        # otherwise the inclusive [start,end] range is searched.
        u.emu_start(0x49b3c4, 0x49b3de, count=50)
        end = struct.unpack('<I', u.mem_read(stack+0x34, 4))[0]
        start = struct.unpack('<I', u.mem_read(stack+0x3c, 4))[0]
        return range(start, end)

    def test_zero_searches_root_socket_and_one_searches_right_hand(self):
        row = ['']*134
        self.assertEqual(list(self.socket_range(row)), [0])
        row[7] = 1
        self.assertEqual(list(self.socket_range(row)), [1])

    def test_generated_guns_search_the_existing_weapon_mount(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        assets = ROOT / 'GundamOnline_CHINA_已解密/decrypted'
        body = (assets/'chara/01/01/0101/model/MSM_0101_0101_01.dxg').read_bytes()
        for row in rows:
            if row[30] != 'GUN_SINGLE':
                continue
            with self.subTest(item=row[0]):
                sockets = list(self.socket_range(row))
                self.assertEqual(sockets, [int(row[11])],
                                 'muzzle search misses held weapon and falls back to actor root')
                for socket in sockets:
                    self.assertIn(f'S_wpn_{socket:02d}'.encode()+b'\0', body)
                resource = int(row[2])
                group, variant = resource//1000000, resource%1000000//100
                model = assets/f'item/{group:02d}/{variant:04d}/model/EM_{group:02d}_{variant:04d}_{resource%100:02d}.dxg'
                self.assertIn(b's_shot01\0', model.read_bytes())

    def test_generated_grenades_search_the_right_hand_mount_without_shot_socket(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        body = (ROOT / 'GundamOnline_CHINA_已解密/decrypted/chara/01/01/0101/model/MSM_0101_0101_01.dxg').read_bytes()
        for row in rows:
            if row[30] != 'HAND_THROW':
                continue
            with self.subTest(item=row[0]):
                sockets = list(self.socket_range(row))
                self.assertEqual(sockets, [int(row[11])],
                                 'throw origin searches S_wpn_00 instead of held right-hand mount')
                self.assertIn(f'S_wpn_{sockets[0]:02d}'.encode()+b'\0', body)
                # Unlike guns, grenade models need not contain s_shot01:
                # 49B5F1 falls through to body S_wpn_NN when none are found.

    def test_native_no_shot_socket_falls_back_to_named_body_mount(self):
        u = projectile_native.ProjectilePresentationNativeTest().machine()
        stack, actor, wrapper, model = 0x20008000, 0x20001000, 0x20003000, 0x20004000
        u.mem_write(stack+0x12, b'\0')  # no shot sockets found in held model
        u.mem_write(stack+0x14, struct.pack('<I', actor))
        u.mem_write(wrapper, struct.pack('<I', model))
        u.mem_write(0x1169254, b'S_wpn_01\0')  # name built by 49B180 range loop
        captured = []

        def lookup(m, address, size, data):
            sp = m.reg_read(UC_X86_REG_ESP)
            if address == 0x48d220:
                self.assertEqual(m.reg_read(UC_X86_REG_ECX), actor)
                ret, dst = struct.unpack('<2I', m.mem_read(sp, 8))
                m.mem_write(dst, struct.pack('<I', model))
                m.reg_write(UC_X86_REG_EAX, dst)
                m.reg_write(UC_X86_REG_ESP, sp+8)
                m.reg_write(UC_X86_REG_EIP, ret)
            elif address == 0xb3a5f0:
                _, name, mode = struct.unpack('<3I', m.mem_read(sp, 12))
                captured.append((m.reg_read(UC_X86_REG_ECX), bytes(m.mem_read(name, 9)), mode))
                m.emu_stop()

        u.hook_add(UC_HOOK_CODE, lookup)
        u.emu_start(0x49b5f1, 0x49b628, count=100)
        self.assertEqual(captured, [(model+0x23c, b'S_wpn_01\0', 0)])


if __name__ == '__main__':
    unittest.main()
