"""Current native jump reader, ascent velocity and hold timeout; no live writes."""
import csv
import io
import struct
import unittest

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EIP,
                              UC_X86_REG_ESP, UC_X86_REG_EBP)
import test_projectile_presentation_native as native
import hangar_experiment


class JumpPhysicsNativeTest(unittest.TestCase):
    def test_release_preserves_upward_speed_without_hundredfold_launch(self):
        machine = native.ProjectilePresentationNativeTest().machine()
        control, actor, definition, physics, vector, stack, stop = (
            0x20001000, 0x20004000, 0x20005000, 0x20007000,
            0x20003000, 0x20008000, 0x20009000)
        self.load_definition(machine, definition)
        upward = struct.unpack('<i', machine.mem_read(definition + 0x134, 4))[0]
        rows = csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_model.csv').decode()))
        model = next(r for r in rows if r and r[0] == str(hangar_experiment.MODEL_ID))
        mass = float(model[11])
        machine.mem_write(control, struct.pack('<III', 0xcb4564, actor, 0))
        machine.mem_write(control + 0x14, struct.pack('<I', 16))
        machine.mem_write(control + 0x4e4, struct.pack('<f', upward))
        machine.mem_write(actor + 0x30c, struct.pack('<I', physics))
        machine.mem_write(physics + 4, struct.pack('<I', actor))
        machine.mem_write(physics + 0x38, struct.pack('<f', mass))
        machine.mem_write(physics + 0x64, struct.pack('<3f', 1, 1, 1))

        def lookup(m, address, size, data):
            if address == 0x473530:
                sp = m.reg_read(UC_X86_REG_ESP)
                ret = struct.unpack('<I', m.mem_read(sp, 4))[0]
                m.reg_write(UC_X86_REG_EAX, definition)
                m.reg_write(UC_X86_REG_ESP, sp + 4)
                m.reg_write(UC_X86_REG_EIP, ret)

        machine.hook_add(UC_HOOK_CODE, lookup)
        machine.mem_write(stack, struct.pack('<III', stop, 0, 0))
        machine.reg_write(UC_X86_REG_ESP, stack)
        machine.reg_write(UC_X86_REG_ECX, control)
        # Actual release callback multiplies cm/s by100 into an impulse.
        machine.emu_start(0x4de430, 0x4de4ad, count=1000)
        machine.mem_write(stack, struct.pack('<IIfI', stop, vector, 1 / 60, 1))
        machine.reg_write(UC_X86_REG_ESP, stack)
        machine.reg_write(UC_X86_REG_ECX, physics)
        # Actual solver multiplies impulse by1/60 and divides by model mass.
        machine.emu_start(0x50d100, stop, count=20000)
        physical_speed = struct.unpack('<f', machine.mem_read(physics + 12, 4))[0]
        self.assertAlmostEqual(physical_speed, upward / 100, delta=upward / 100 * .01,
                               msg='release must preserve cm/s -> m/s, not turn a tap into a map-ceiling launch')

    def profile(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_settings.csv').decode())))
        unit = next(r for r in rows if r and r[0] == str(hangar_experiment.MSMA_ID))
        details = list(csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_battle_detail.csv').decode())))
        row = next((r for r in details if len(r) > 1 and r[:2] == ['JUMP', unit[79]]), None)
        # 54E2F0 missing-template branch zeros all twelve fields.
        if row is None:
            return bytes(48)
        machine = native.ProjectilePresentationNativeTest().machine()
        stack, target, floating, stub, stop = 0x20008000, 0x20001000, 0x20002000, 0x20003000, 0x20009000
        machine.mem_write(stub, b'\xd9\x05' + struct.pack('<I', floating) + b'\xc3')
        machine.mem_write(stack, struct.pack('<III', stop, 0, target))
        machine.reg_write(UC_X86_REG_ESP, stack)

        def scalar(m, address, size, data):
            if address not in (0xb08260, 0xb081e0):
                return
            sp = m.reg_read(UC_X86_REG_ESP)
            ret, _, column = struct.unpack('<III', m.mem_read(sp, 12))
            value = row[column] if column < len(row) else '0'
            if address == 0xb08260:
                m.mem_write(floating, struct.pack('<f', float(value)))
                m.reg_write(UC_X86_REG_EIP, stub)
            else:
                m.reg_write(UC_X86_REG_EAX, int(value))
                m.reg_write(UC_X86_REG_ESP, sp + 4)
                m.reg_write(UC_X86_REG_EIP, ret)

        machine.hook_add(UC_HOOK_CODE, scalar)
        machine.emu_start(0x5498a0, stop, count=1000)
        return bytes(machine.mem_read(target, 48))

    def load_definition(self, machine, definition):
        source = 0x20006000
        machine.mem_write(source, self.profile())
        machine.reg_write(UC_X86_REG_EAX, source)
        machine.reg_write(UC_X86_REG_EBP, definition)
        # Actual 54E2F0 finalization includes the signed descent conversion.
        machine.emu_start(0x54e624, 0x54e6dd, count=100)

    def test_held_jump_has_upward_velocity_and_does_not_timeout_immediately(self):
        profile = self.profile()
        machine = native.ProjectilePresentationNativeTest().machine()
        control, actor, definition, stack, stop = 0x20001000, 0x20004000, 0x20005000, 0x20008000, 0x20009000
        machine.mem_write(control, struct.pack('<III', 0xcb4564, actor, 0))
        self.load_definition(machine, definition)
        machine.mem_write(control + 0x1c4, profile[:4])
        expired = []

        def external(m, address, size, data):
            result, arguments = None, 0
            if address == 0x473530:
                result = definition
            elif address in (0x475b50, 0x493670):
                result = 0  # ordinary ground map, no underwater multiplier
            elif address in (0x4decf0, 0x4df760):
                result, arguments = 0, 4
                if address == 0x4df760:
                    expired.append(True)
            if result is not None:
                sp = m.reg_read(UC_X86_REG_ESP)
                ret = struct.unpack('<I', m.mem_read(sp, 4))[0]
                m.reg_write(UC_X86_REG_EAX, result)
                m.reg_write(UC_X86_REG_ESP, sp + 4 + arguments)
                m.reg_write(UC_X86_REG_EIP, ret)

        machine.hook_add(UC_HOOK_CODE, external)
        for _ in range(60):
            machine.mem_write(stack, struct.pack('<IfI', stop, 1 / 60, 0))
            machine.reg_write(UC_X86_REG_ESP, stack)
            machine.reg_write(UC_X86_REG_ECX, control)
            machine.emu_start(0x4df0c0, stop, count=1000)
        self.assertFalse(expired, 'zero JUMP duration forces native ascent to end on its first tick')
        self.assertGreater(struct.unpack('<f', machine.mem_read(control + 0x4e4, 4))[0], 100,
                           'native ascent reads zero upward velocity from the missing JUMP template')
        for _ in range(120):
            machine.mem_write(stack, struct.pack('<IfI', stop, 1 / 60, 0))
            machine.reg_write(UC_X86_REG_ESP, stack)
            machine.reg_write(UC_X86_REG_ECX, control)
            machine.emu_start(0x4df0c0, stop, count=1000)
        self.assertTrue(expired, 'ordinary jump must retain its native maximum-ascent timer')

    def test_post_ascent_phase_uses_slow_descent_and_nonzero_boost_costs(self):
        machine = native.ProjectilePresentationNativeTest().machine()
        control, actor, definition, physics, stack, stop = (
            0x20001000, 0x20004000, 0x20005000, 0x20007000, 0x20008000, 0x20009000)
        machine.mem_write(control, struct.pack('<III', 0xcb4564, actor, 0))
        machine.mem_write(actor + 0x30c, struct.pack('<I', physics))
        self.load_definition(machine, definition)

        def lookup(m, address, size, data):
            if address == 0x473530:
                sp = m.reg_read(UC_X86_REG_ESP)
                ret = struct.unpack('<I', m.mem_read(sp, 4))[0]
                m.reg_write(UC_X86_REG_EAX, definition)
                m.reg_write(UC_X86_REG_ESP, sp + 4)
                m.reg_write(UC_X86_REG_EIP, ret)

        machine.hook_add(UC_HOOK_CODE, lookup)
        machine.mem_write(stack, struct.pack('<IfI', stop, 1 / 60, 0))
        machine.reg_write(UC_X86_REG_ESP, stack)
        machine.reg_write(UC_X86_REG_ECX, control)
        machine.emu_start(0x4dee20, stop, count=1000)
        descent = struct.unpack('<f', machine.mem_read(control + 0x4e4, 4))[0]
        self.assertLess(descent, 0)
        self.assertGreater(descent, -200)
        for offset in (0x12c, 0x138, 0x140):
            self.assertGreater(struct.unpack('<i', machine.mem_read(definition + offset, 4))[0], 0)


if __name__ == '__main__':
    unittest.main()
