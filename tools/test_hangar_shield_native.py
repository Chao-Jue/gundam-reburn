"""Real shield UI renderer with the static item lookup and widgets substituted."""
import csv
import io
from pathlib import Path
import struct
import sys
import unittest
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_ECX,
                              UC_X86_REG_EAX, UC_X86_REG_ESI, UC_X86_REG_EDI)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'server'))
import hangar_experiment as experiment
from hangar import unit_wire
from emulate_wire_reader import decode


class ShieldNativeTest(unittest.TestCase):
    def test_equipped_id_and_native_ui_durability(self):
        unit = experiment.gm_unit()
        ok, _, wire = decode(0xa96070, unit_wire(unit))
        self.assertEqual(ok, 1)
        item_id = struct.unpack_from('<I', wire, 0x78)[0]
        self.assertEqual(item_id, 777104)
        rows = list(csv.reader(io.StringIO(experiment.table_body('item/weapon_battle_detail.csv').decode())))[2:]
        hp = int(next(r for r in rows if r[:2] == ['SHIELD', 'GM_SHIELD_HP'])[2])
        image = (ROOT/'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000, (len(image)+4095)&~4095)
        u.mem_write(0x400000, image)
        u.mem_map(0x20000000, 0x20000)
        obj, stats, table, node, weapon, widget, vt, sp, end = [0x20001000+i*0x1000 for i in range(9)]
        u.mem_write(0x1161f88, struct.pack('<I', table))
        msma = list(csv.reader(io.StringIO(experiment.table_body('msma/msma_settings.csv').decode())))[2]
        # Execute real54EF50 assignment: col44 -> model definition+16C.
        u.reg_write(UC_X86_REG_ESP, sp)
        u.reg_write(UC_X86_REG_ESI, stats)
        u.reg_write(UC_X86_REG_EDI, 0x20000000)

        def csv_int(m, a, size, data):
            if a != 0xb081e0:
                return
            p = m.reg_read(UC_X86_REG_ESP)
            ret, _, column = struct.unpack('<III', m.mem_read(p, 12))
            self.assertEqual(column, 44)
            m.reg_write(UC_X86_REG_EAX, int(msma[column]))
            m.reg_write(UC_X86_REG_ESP, p+4)
            m.reg_write(UC_X86_REG_EIP, ret)

        csv_hook = u.hook_add(UC_HOOK_CODE, csv_int)
        u.emu_start(0x54f3d8, 0x54f3ef, count=50)
        u.hook_del(csv_hook)
        self.assertEqual(struct.unpack('<I', u.mem_read(stats+0x16c, 4))[0], item_id)
        u.mem_write(node+0x5c, struct.pack('<I', weapon))
        u.mem_write(weapon+0x974, struct.pack('<I', 4))
        u.mem_write(weapon+0x78c, struct.pack('<I', hp))
        for offset in (0x178, 0x180):
            u.mem_write(obj+offset, struct.pack('<I', widget))
        u.mem_write(widget, struct.pack('<I', vt))
        for offset in (0x1ac, 0x290, 0x2a8):
            u.mem_write(vt+offset, struct.pack('<I', vt+offset+0x400))
        u.mem_write(sp, struct.pack('<III', end, stats, 1))
        u.reg_write(UC_X86_REG_ESP, sp)
        u.reg_write(UC_X86_REG_ECX, obj)
        displayed = []

        def hook(m, a, size, data):
            p = m.reg_read(UC_X86_REG_ESP)
            if a == 0x85a8c0:
                ret, out, key = struct.unpack('<III', m.mem_read(p, 12))
                self.assertEqual(struct.unpack('<I', m.mem_read(key, 4))[0], item_id)
                m.mem_write(out, struct.pack('<I', node))
                pop = 12
            elif a in (vt+0x5ac, vt+0x690, vt+0x6a8):
                ret, value = struct.unpack('<II', m.mem_read(p, 8))
                if a == vt+0x690:
                    displayed.append(value)
                pop = {vt+0x5ac: 16, vt+0x690: 12, vt+0x6a8: 8}[a]
            else:
                return
            m.reg_write(UC_X86_REG_ESP, p+pop)
            m.reg_write(UC_X86_REG_EIP, ret)

        u.hook_add(UC_HOOK_CODE, hook)
        u.emu_start(0x792fb0, end, count=1000)
        self.assertEqual(displayed, [990])


if __name__ == '__main__':
    unittest.main()
