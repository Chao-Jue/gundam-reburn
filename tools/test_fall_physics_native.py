"""Current native vertical displacement scaling; no live process modifications."""
import unittest
import struct
from unicorn.x86_const import UC_X86_REG_ECX, UC_X86_REG_ESP
import test_projectile_presentation_native as native
import hangar_experiment


class FallPhysicsNativeTest(unittest.TestCase):
    def displacement(self, ratio):
        machine=native.ProjectilePresentationNativeTest().machine()
        physics,vector,stack,stop=0x20001000,0x20002000,0x20008000,0x20009000
        machine.mem_write(physics+0x30,struct.pack('<f',-9.80665))
        machine.mem_write(physics+0x38,struct.pack('<f',1))
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
