"""Native weapon collision flags and gun actor-hit dispatch gate."""
import csv
import io
import struct
import unittest
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EAX, UC_X86_REG_EIP
import test_projectile_presentation_native as native
import hangar_experiment


class WeaponHitGateNativeTest(unittest.TestCase):
    def actor_dispatch(self, row):
        u = native.ProjectilePresentationNativeTest().machine()
        definition = 0x20001000
        u.reg_write(UC_X86_REG_ESI, definition)
        u.reg_write(UC_X86_REG_EDI, 0x20003000)
        def integer(m, address, size, data):
            if address != 0xb081e0:
                return
            sp = m.reg_read(UC_X86_REG_ESP)
            ret, source, col = struct.unpack('<3I', m.mem_read(sp, 12))
            self.assertIn(col, (33, 34))
            m.reg_write(UC_X86_REG_EAX, int(row[col] or 0))
            m.reg_write(UC_X86_REG_ESP, sp+4)
            m.reg_write(UC_X86_REG_EIP, ret)
        hook = u.hook_add(UC_HOOK_CODE, integer)
        u.emu_start(0x55c7f3, 0x55c831, count=100)
        u.hook_del(hook)
        flags = u.mem_read(definition+0x814, 1)[0]
        u.reg_write(UC_X86_REG_EDI, definition)
        reached = []
        def stop(m, address, size, data):
            if address in (0x50593f, 0x50597d):
                reached.append(address)
                m.emu_stop()
        u.hook_add(UC_HOOK_CODE, stop)
        u.emu_start(0x505936, 0x505980, count=20)
        self.assertTrue(reached)
        return reached[0] == 0x50593f, flags

    def test_empty_actor_hit_flag_skips_and_enabled_enters_native_dispatch(self):
        row = ['']*134
        self.assertEqual(self.actor_dispatch(row), (False, 0))
        row[33] = row[34] = 1
        self.assertEqual(self.actor_dispatch(row), (True, 3))

    def test_generated_guns_enable_native_actor_and_world_hits(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        for row in rows:
            if row[30] == 'GUN_SINGLE':
                with self.subTest(item=row[0]):
                    enters, flags = self.actor_dispatch(row)
                    self.assertTrue(enters, 'gun collides visually but skips 4EC9A0 actor-hit dispatch')
                    self.assertEqual(flags & 3, 3)


class BulletHitReportNativeTest(unittest.TestCase):
    def report_gate(self, value):
        u = native.ProjectilePresentationNativeTest().machine()
        bullet, text, projectile, hit, wrapper = (0x20001000, 0x20002000,
                                                 0x20003000, 0x20004000, 0x20005000)
        encoded = value.encode('ascii')
        self.assertLess(len(encoded), 16)
        u.mem_write(text+4, encoded+b'\0')
        u.mem_write(text+0x14, struct.pack('<2I', len(encoded), 15))
        u.reg_write(UC_X86_REG_EAX, text)
        u.reg_write(UC_X86_REG_EDI, bullet)
        # Execute the real CSV3 ON/OFF comparisons and bullet+4 assignment.
        u.emu_start(0x53f239, 0x53f281, count=500)
        flag = u.mem_read(bullet+4, 1)[0]
        u.mem_write(projectile+0x10, struct.pack('<I', bullet))
        u.mem_write(hit, struct.pack('<I', wrapper))
        u.mem_write(wrapper, struct.pack('<I', 0x20006000))
        u.reg_write(UC_X86_REG_ESI, projectile)
        u.reg_write(UC_X86_REG_EDI, hit)
        reached = []
        def stop(m, address, size, data):
            if address in (0x4ec9da, 0x4ec9ee):
                reached.append(address)
                m.emu_stop()
        u.hook_add(UC_HOOK_CODE, stop)
        u.emu_start(0x4ec9cd, 0x4ec9f0, count=30)
        self.assertTrue(reached)
        return reached[0] == 0x4ec9da, flag

    def test_native_bullet_requires_literal_on_to_report_actor_hit(self):
        for value in ('', '0', '1', 'OFF'):
            with self.subTest(value=value):
                self.assertEqual(self.report_gate(value), (False, 0))
        self.assertEqual(self.report_gate('ON'), (True, 1))

    def test_generated_guns_enable_bullet_hit_report(self):
        guns = {str(w['item_id']) for w in hangar_experiment.all_definitions()
                if w.get('projectile_presentation')}
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/bullet.csv').decode())))[2:]
        for row in rows:
            if row[0] in guns:
                with self.subTest(item=row[0]):
                    self.assertEqual(self.report_gate(row[3]), (True, 1),
                                     'native collision skips 4EBB70 hit report when bullet CSV3 is not ON')
