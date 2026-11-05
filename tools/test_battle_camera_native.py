"""Run the native camera-distance calculation using the generated GM model row."""
import csv
import io
import struct
import sys
import unittest
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EAX, UC_X86_REG_EIP

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment


def native_distance(override):
    image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    u.mem_map(0x400000, (len(image) + 4095) & ~4095)
    u.mem_write(0x400000, image)
    u.mem_map(0x20000000, 0x100000)
    view, actor, model, ref, vacant, options = [0x20000000 + i * 0x1000 for i in range(6)]
    stack, result, stop = 0x20080000, 0x20090000, 0x200a0000
    def word(address, value):
        u.mem_write(address, struct.pack('<I', value))
    word(view + 0x18, ref)
    word(ref, actor)
    word(actor + 0x10, model)
    word(actor + 0x634, vacant)
    u.mem_write(model + 0x34, struct.pack('<f', override))
    word(0x1161f68, options)
    word(options + 0x10, 1)
    # Capture the real x87 return value without replacing native helpers.
    word(stack, stop)
    u.mem_write(stop, b'\xd9\x1d' + struct.pack('<I', result))
    u.reg_write(UC_X86_REG_ESP, stack)
    u.reg_write(UC_X86_REG_ECX, view)
    u.emu_start(0xa23120, stop + 6, count=10000)
    return struct.unpack('<f', u.mem_read(result, 4))[0]


class BattleCameraNativeTest(unittest.TestCase):
    def test_owned_gm_is_eligible_for_native_visibility_refresh(self):
        rows = csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_model.csv').decode()))
        row = next(r for r in rows if r and r[0] == str(hangar_experiment.MODEL_ID))
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000, (len(image) + 4095) & ~4095)
        u.mem_write(0x400000, image)
        u.mem_map(0x20000000, 0x100000)
        actor, model, stack, stop = 0x20000000, 0x20001000, 0x20080000, 0x200a0000
        u.mem_write(actor + 0x10, struct.pack('<I', model))
        u.mem_write(actor + 0xd8, struct.pack('<I', 0x20002000))
        u.mem_write(actor + 0x358, b'\x01')
        u.mem_write(model + 0x32, bytes([int(row[14]) != 0]))
        u.mem_write(stack, struct.pack('<I', stop))
        u.reg_write(UC_X86_REG_ESP, stack)
        u.reg_write(UC_X86_REG_ECX, actor)
        u.emu_start(0x474670, stop, count=1000)
        self.assertEqual(u.reg_read(UC_X86_REG_EAX) & 255, 1,
                         'model column14=0 prevents owned-entity visibility refresh')

    def test_gm_focus_height_is_raised_for_clearer_battle_view(self):
        rows = csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_model.csv').decode()))
        row = next(r for r in rows if r and r[0] == str(hangar_experiment.MODEL_ID))
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0, 0x1000)
        u.mem_map(0x400000, (len(image) + 4095) & ~4095)
        u.mem_write(0x400000, image)
        u.mem_map(0x20000000, 0x100000)
        actor, model, stack, stop, result = 0x20000000, 0x20001000, 0x20080000, 0x200a0000, 0x20090000
        u.mem_write(actor + 0x10, struct.pack('<I', model))
        u.mem_write(model + 4, struct.pack('<f', float(row[1])))
        u.mem_write(stack, struct.pack('<I', stop))
        u.mem_write(stop, b'\xd9\x1d' + struct.pack('<I', result))
        # Isolate the native height accessor's no-render-interface branch.
        def no_interface(machine, address, size, data):
            if address == 0x48d220:
                sp = machine.reg_read(UC_X86_REG_ESP)
                ret, out = struct.unpack('<II', machine.mem_read(sp, 8))
                machine.mem_write(out, bytes(4))
                machine.reg_write(UC_X86_REG_EAX, out)
                machine.reg_write(UC_X86_REG_ESP, sp + 8)
                machine.reg_write(UC_X86_REG_EIP, ret)
        u.hook_add(UC_HOOK_CODE, no_interface)
        u.reg_write(UC_X86_REG_ESP, stack)
        u.reg_write(UC_X86_REG_ECX, actor)
        u.emu_start(0x477950, stop + 6, count=10000)
        self.assertAlmostEqual(struct.unpack('<f', u.mem_read(result, 4))[0], 220.0)

    def test_gm_model_uses_default_third_person_distance(self):
        rows = csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_model.csv').decode()))
        row = next(r for r in rows if r and r[0] == str(hangar_experiment.MODEL_ID))
        self.assertAlmostEqual(native_distance(float(row[15])), 550.0, places=3,
                               msg='diagnostic value 1 overrides the camera distance to 0.1')

    def test_native_nonzero_override_reproduces_the_near_zero_distance(self):
        self.assertAlmostEqual(native_distance(1), 0.1, places=5)


if __name__ == '__main__':
    unittest.main()
