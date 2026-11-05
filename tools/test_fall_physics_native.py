"""Current native vertical displacement scaling; no live process modifications."""
import unittest
import struct
import csv
import io
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_ECX, UC_X86_REG_ESP, UC_X86_REG_ESI,
                              UC_X86_REG_EAX, UC_X86_REG_EBP)
import test_projectile_presentation_native as native
import hangar_experiment


class FallPhysicsNativeTest(unittest.TestCase):
    def remaining_step_offset(self, height):
        machine = native.ProjectilePresentationNativeTest().machine()
        actor, model, stack, frame, stub = 0x20001000, 0x20002000, 0x20008000, 0x20007000, 0x20009000
        machine.mem_write(actor + 0x10, struct.pack('<I', model))
        machine.mem_write(model + 0x18, struct.pack('<f', height))
        machine.reg_write(UC_X86_REG_ESI, actor)
        machine.reg_write(UC_X86_REG_EAX, 0)
        # Native 4958A0 guard: zero model step height bypasses visual step
        # compensation. The terrain collision result itself is unchanged.
        branches = []
        def guard_stop(m, address, size, data):
            if address in (0x495c09, 0x495a97):
                branches.append(address)
                m.emu_stop()
        hook = machine.hook_add(UC_HOOK_CODE, guard_stop)
        machine.emu_start(0x4958e7, 0x495c10, count=80)
        machine.hook_del(hook)
        if branches == [0x495c09]:
            return 0.0  # native visual compensation is bypassed
        if branches != [0x495a97]:
            raise AssertionError('step guard did not reach an expected branch')
        machine.mem_write(actor + 0x2dc, struct.pack('<f', 100))
        machine.mem_write(frame + 8, struct.pack('<f', 1 / 60))
        machine.reg_write(UC_X86_REG_EBP, frame)
        # fninit; fldz (new floor); push native arithmetic; ret.
        machine.mem_write(stub, b'\xdb\xe3\xd9\xee\x68' + struct.pack('<I', 0x495b0c) + b'\xc3')
        for _ in range(60):
            machine.reg_write(UC_X86_REG_ESP, stack)
            machine.emu_start(stub, 0x495b87, count=100)
        return struct.unpack('<f', machine.mem_read(actor + 0x2dc, 4))[0]

    def test_model_does_not_leave_centimeter_placeholder_step_smoothing_active(self):
        rows = csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_model.csv').decode()))
        row = next(r for r in rows if r and r[0] == str(hangar_experiment.MODEL_ID))
        self.assertLess(self.remaining_step_offset(float(row[5])), 5,
                        'a 1m terrain step still leaves the body almost 1m above its collision floor after 1s')

    def displacement(self, ratio, mass=1):
        machine=native.ProjectilePresentationNativeTest().machine()
        physics,vector,stack,stop=0x20001000,0x20002000,0x20008000,0x20009000
        machine.mem_write(physics+0x30,struct.pack('<f',-9.80665 * mass))
        machine.mem_write(physics+0x38,struct.pack('<f',mass))
        machine.mem_write(physics+0x64,struct.pack('<fff',1,ratio,1))
        machine.mem_write(stack,struct.pack('<IIfI',stop,vector,.1,0))
        machine.reg_write(UC_X86_REG_ECX,physics);machine.reg_write(UC_X86_REG_ESP,stack)
        machine.emu_start(0x50d100,stop,count=20000)
        return struct.unpack('<f',machine.mem_read(vector+4,4))[0]

    def test_generated_experiment_applies_normal_vertical_displacement(self):
        data=hangar_experiment.table_body('autoexec_sv.cfg').decode('utf-8')
        values={line.split(',')[0]:line.split(',')[1] for line in data.splitlines()
                if ',' in line and not line.startswith('#')}
        ratio=float(values.get('move_building_rate',.1))
        self.assertAlmostEqual(self.displacement(ratio),self.displacement(1.),places=4,
                               msg='missing move_building_rate retains native 0.1 vertical displacement')

    def test_native_tenth_ratio_reduces_same_gravity_displacement_tenfold(self):
        self.assertLess(self.displacement(1),0)
        self.assertAlmostEqual(self.displacement(.1)*10,self.displacement(1),places=4)

    def test_configured_body_mass_preserves_free_fall_acceleration(self):
        rows = csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_model.csv').decode()))
        model = next(r for r in rows if r and r[0] == str(hangar_experiment.MODEL_ID))
        self.assertAlmostEqual(self.displacement(1, float(model[11])), self.displacement(1, 1), places=4)
