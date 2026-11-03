"""Execute the native hold-category enum and joint-route selector offline."""
import csv
import io
import struct
import sys
import unittest
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EIP, UC_X86_REG_ESP

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment


class WeaponAimRouteNativeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()

    def machine(self):
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0, 0x1000)
        u.mem_map(0x400000, (len(self.image)+4095)&~4095)
        u.mem_write(0x400000, self.image)
        u.mem_map(0x20000000, 0x10000)
        return u

    def category(self, token):
        u = self.machine()
        stack, stop = 0x20008000, 0x20009000
        raw = token.encode('ascii')
        self.assertLessEqual(len(raw), 15)
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
        u.emu_start(0x55af70, stop, count=10000)
        return u.reg_read(UC_X86_REG_EAX)

    def route(self, category, *, aiming=True, model_category=0):
        u = self.machine()
        joint, actor, weapon, definition, model = [0x20000000+i*0x1000 for i in range(5)]
        stack, stop = 0x20008000, 0x20009000
        def put(address, value):
            u.mem_write(address, struct.pack('<I', value))
        put(joint+0xac, actor)
        put(joint+0xbc, 13)  # MSJ_0101.csv has 13 ROUTE rows.
        put(actor+0x10, model)
        put(weapon+4, definition)
        put(definition+0x28, category)  # 55C3E0 CSV13 -> 55AF70 -> +28.
        put(model+0x174, model_category)
        put(stack, stop)
        u.reg_write(UC_X86_REG_ECX, joint)
        u.reg_write(UC_X86_REG_ESP, stack)
        # Only replace external actor-state queries. Execute every selection,
        # definition-field read, fallback and range check in actual 50A900.
        query_results = {0x4736f0: 0, 0x471cf0: weapon, 0x48d1f0: int(aiming)}
        def query(m, address, size, data):
            if address not in query_results:
                return
            sp = m.reg_read(UC_X86_REG_ESP)
            ret = struct.unpack('<I', m.mem_read(sp, 4))[0]
            m.reg_write(UC_X86_REG_EAX, query_results[address])
            m.reg_write(UC_X86_REG_ESP, sp+4)
            m.reg_write(UC_X86_REG_EIP, ret)
        u.hook_add(UC_HOOK_CODE, query)
        u.emu_start(0x50a900, stop, count=1000)
        self.assertEqual(u.reg_read(UC_X86_REG_EIP), stop)
        return u.reg_read(UC_X86_REG_EAX)

    def test_native_default_onehand_idle_and_model_origin_routes(self):
        self.assertEqual(self.category(''), 0)
        self.assertEqual(self.category('ONEHAND'), 2)
        self.assertEqual(self.route(0), 0)
        self.assertEqual(self.route(2), 2)
        self.assertEqual(self.route(2, aiming=False), 0)
        self.assertEqual(self.route(self.category('MODELORIGIN'), model_category=2), 2)
        self.assertEqual(self.route(13), 0)

    def test_generated_guns_choose_right_arm_route_when_aiming(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        guns = [row for row in rows if row[30] == 'GUN_SINGLE']
        self.assertEqual({int(row[0]) for row in guns}, {777101, 777105, 777108})
        for row in guns:
            with self.subTest(item=row[0]):
                category = self.category(row[13])
                self.assertEqual(self.route(category), 2,
                                 'blank hold category selects default head route0')
                self.assertEqual(self.route(category, aiming=False), 0)

    def test_gm_onehand_route_includes_right_arm_and_spine(self):
        # Check local asset relationships without copying the client's table.
        source = ROOT / 'GundamOnline_CHINA_已解密/decrypted/chara/01/01/MSJ_0101.csv'
        rows = list(csv.reader(io.StringIO(source.read_text(encoding='utf-8-sig'))))
        joints = [row[2] for row in rows if row[0] == 'JOINT']
        routes = [row for row in rows if row[0] == 'ROUTE']
        names = lambda index: {joints[int(n)] for n in routes[index][3:]}
        self.assertEqual(names(0), {'T_head', 'C_Spine'})
        self.assertEqual(names(2), {'T_R_UpperArm', 'C_Spine'})


if __name__ == '__main__':
    unittest.main()
