"""Execute the model gait scalar mapping and native locomotion selector.

No renderer, live process, client assets or animation playback are modified.
"""
import csv
import io
import struct
import sys
import unittest
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX,
                              UC_X86_REG_ECX, UC_X86_REG_ESI, UC_X86_REG_EDI,
                              UC_X86_REG_EBP)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment


class WalkCycleNativeTest(unittest.TestCase):
    def selector(self, gait):
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000, (len(image)+4095)&~4095)
        u.mem_write(0x400000, image)
        u.mem_map(0x20000000, 0x10000)
        actor, model, controller, vtable, stub, stack, stop = [
            0x20001000+i*0x1000 for i in range(7)]
        u.mem_write(actor+0x10, struct.pack('<I', model))
        u.mem_write(actor+0x280, struct.pack('<I', controller))
        u.mem_write(controller, struct.pack('<I', vtable))
        u.mem_write(vtable+0x58, struct.pack('<I', stub))
        u.mem_write(stub, b'\xb8\x02\x00\x00\x00\xc3')  # walking state

        def primitive(m, address, size, data):
            if address not in (0xb081e0, 0x473c00):
                return
            sp = m.reg_read(UC_X86_REG_ESP)
            ret = struct.unpack('<I', m.mem_read(sp, 4))[0]
            if address == 0xb081e0:
                column = struct.unpack('<I', m.mem_read(sp+8, 4))[0]
                self.assertEqual(column, 45)
                value = gait
            else:
                value = 0  # ordinary ground locomotion, no special posture
            m.reg_write(UC_X86_REG_EAX, value)
            m.reg_write(UC_X86_REG_ESP, sp+4)
            m.reg_write(UC_X86_REG_EIP, ret)

        u.hook_add(UC_HOOK_CODE, primitive)
        # Actual 53FA30 row-parser block: CSV col45 -> model+10C.
        u.reg_write(UC_X86_REG_ESP, stack)
        u.reg_write(UC_X86_REG_ESI, 45)
        u.reg_write(UC_X86_REG_EDI, 0x20008000)
        u.reg_write(UC_X86_REG_EBP, model)
        u.emu_start(0x53fd56, 0x53fd6e, count=100)
        self.assertEqual(struct.unpack('<I', u.mem_read(model+0x10c, 4))[0], gait)

        def select(commit=1):
            u.mem_write(stack, struct.pack('<4I', stop, commit, 0x20009000, 0x20009004))
            u.reg_write(UC_X86_REG_ESP, stack)
            u.reg_write(UC_X86_REG_ECX, actor)
            u.emu_start(0x48cc30, stop, count=1000)
            self.assertEqual(u.reg_read(UC_X86_REG_EIP), stop)
            return u.reg_read(UC_X86_REG_EAX)
        return select

    def test_native_gait_modes_and_preview(self):
        for mode, expected in ((0, [3]*5), (1, [2, 3, 3, 3, 3]),
                               (2, [2, 3, 4, 3, 4])):
            with self.subTest(mode=mode):
                select = self.selector(mode)
                self.assertEqual(select(0), expected[0])
                self.assertEqual(select(0), expected[0])
                self.assertEqual([select() for _ in range(5)], expected)

    def test_experimental_gm_uses_native_alternating_half_steps(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.table_body(
            'msma/msma_model.csv').decode())))[2:]
        row = next(r for r in rows if int(r[0]) == hangar_experiment.MODEL_ID)
        # Missing trailing CSV fields are parsed as zero by the scalar reader.
        select = self.selector(int(row[45] or 0) if len(row) > 45 else 0)
        self.assertEqual([select() for _ in range(5)], [2, 3, 4, 3, 4])


if __name__ == '__main__':
    unittest.main()
