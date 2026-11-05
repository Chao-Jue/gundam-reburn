"""Execute native directional boost multipliers; no live process changes."""
import csv
import io
import struct
import sys
import unittest
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EBX
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment

class BoostDirectionNativeTest(unittest.TestCase):
    def factor(self, side, rear, rear_branch):
        raw = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000, (len(raw)+4095)&~4095)
        u.mem_write(0x400000, raw)
        u.mem_map(0x20000000, 0x10000)
        stats, stack, stub, stop, values = 0x20001000, 0x20004000, 0x20006000, 0x20007000, 0x20008000
        u.mem_write(stats+0x110, struct.pack('<2f', side, rear))
        u.mem_write(values, struct.pack('<2f', 0.0 if rear_branch else 1.0, 1.0))
        # At either native arithmetic tail ST0=1 and ST1=directional weight (side=1, rear=0).
        code = b'\xd9\x05'+struct.pack('<I',values)+b'\xd9\x05'+struct.pack('<I',values+4)
        tail = 0x4de68c if rear_branch else 0x4de676
        code += b'\xe9'+struct.pack('<i',tail-(stub+len(code)+5))
        u.mem_write(stub,code)
        u.mem_write(stack+8+0x28,struct.pack('<I',stop))
        u.reg_write(UC_X86_REG_ESP,stack)
        u.reg_write(UC_X86_REG_EBX,stats)
        # Store x87 return as float after the native epilogue.
        u.mem_write(stop,b'\xd9\x1d'+struct.pack('<I',values+8))
        u.emu_start(stub,stop+6,count=100)
        return struct.unpack('<f',u.mem_read(values+8,4))[0]

    def test_native_direction_controls(self):
        for side,rear,branch,expected in [(0,0,False,0), (0,0,True,0),(.8,.6,False,.8),(.8,.6,True,.6),(1,1,False,1),(1,1,True,1)]:
            with self.subTest(side=side,rear=rear,branch=branch):
                self.assertAlmostEqual(self.factor(side,rear,branch),expected,places=5)

    def test_experiment_does_not_zero_directional_boost_speed(self):
        rows=list(csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_battle_detail.csv').decode())))[2:]
        row=next(r for r in rows if r[0]=='BOOST_SPEED')
        # 54E2F0 maps values[7:9] to +110/+114; 4DE520 consumes them.
        side,rear=map(float,row[9:11])
        for branch in (False,True):
            with self.subTest(rear_branch=branch):
                self.assertGreater(self.factor(side,rear,branch),0,
                    'generated curve collapses this native directional multiplier to zero')

class BoostConsumptionNativeTest(unittest.TestCase):
    def consume(self, cost, alternate=False):
        from unicorn.x86_const import UC_X86_REG_EAX
        raw=(ROOT/'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u=Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000,(len(raw)+4095)&~4095);u.mem_write(0x400000,raw)
        u.mem_map(0x20000000,0x10000)
        stats,stack,out=0x20001000,0x20004000,0x20008000
        u.mem_write(stats+(0x108 if alternate else 0xfc),struct.pack('<i',cost))
        u.mem_write(stack,struct.pack('<If',0,0.0))  # saved ESI, zero reduction
        u.reg_write(UC_X86_REG_EAX,stats);u.reg_write(UC_X86_REG_ESP,stack)
        u.emu_start(0x4e3566 if alternate else 0x4e3526,0xc12e30,count=100)
        # Capture the native pre-conversion x87 result without replacing math.
        u.mem_write(0x20006000,b'\xd9\x1d'+struct.pack('<I',out))
        u.emu_start(0x20006000,0x20006006,count=10)
        return struct.unpack('<f',u.mem_read(out,4))[0]

    def test_consumption_controls(self):
        for alt in (False,True):
            for cost in (0,100):
                self.assertEqual(self.consume(cost,alt),cost)

    def test_generated_boost_has_native_consumption(self):
        rows=list(csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_battle_detail.csv').decode())))[2:]
        row=next(r for r in rows if r[0]=='BOOST_SPEED')
        for column,alt in ((4,False),(7,True)):
            with self.subTest(column=column):
                self.assertGreater(self.consume(int(row[column]),alt),0,
                    'zero native boost cost cannot consume propellant')

if __name__ == '__main__':
    unittest.main()
