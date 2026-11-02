"""Execute the native visual factory; excludes asset loading and rendering."""
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


class WeaponFactoryNativeTest(unittest.TestCase):
    def factory(self, mount):
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0, 0x1000)
        u.mem_map(0x400000, (len(image)+4095)&~4095)
        u.mem_write(0x400000, image)
        u.mem_map(0x20000000, 0x10000)
        table, node, definition, obj, stack, stop = [0x20001000+i*0x1000 for i in range(6)]
        u.mem_write(0x1161f88, struct.pack('<I', table))
        u.mem_write(table+8, struct.pack('<I', table+0x100))
        u.mem_write(node+0x10+0x4c, struct.pack('<I', definition))
        # 55C3E0 CSV column11 -> definition+20 (verified consumer 4E1F00).
        u.mem_write(definition+0x20, struct.pack('<I', mount))
        u.mem_write(stack, struct.pack('<9I', stop, 0, 777108, 0, 0, 0, 0, 0, 0))
        u.reg_write(UC_X86_REG_ESP, stack)

        def external(m, address, size, data):
            if address not in (0x85a8c0, 0xb29490):
                return
            sp = m.reg_read(UC_X86_REG_ESP)
            ret = struct.unpack('<I', m.mem_read(sp, 4))[0]
            if address == 0x85a8c0:
                out = struct.unpack('<I', m.mem_read(sp+4, 4))[0]
                m.mem_write(out, struct.pack('<I', node))
                m.reg_write(UC_X86_REG_ESP, sp+12)
            else:
                m.reg_write(UC_X86_REG_EAX, obj)
                m.reg_write(UC_X86_REG_ESP, sp+4)
            m.reg_write(UC_X86_REG_EIP, ret)

        u.hook_add(UC_HOOK_CODE, external)
        u.emu_start(0x4e1f00, stop, count=2000)
        self.assertEqual(u.reg_read(UC_X86_REG_EIP), stop)
        return struct.unpack('<I', u.mem_read(obj, 4))[0]

    def test_generated_weapons_and_shield_select_model_capable_factory(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        for row in rows:
            with self.subTest(item=row[0]):
                self.assertEqual(self.factory(int(row[11] or 0)), 0xcb5e54,
                                 'empty mount creates a base object without model loading')

    def test_zero_mount_is_the_native_non_rendering_base_class(self):
        self.assertEqual(self.factory(0), 0xcb5ecc)
