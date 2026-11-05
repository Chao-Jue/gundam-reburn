"""Execute native attack scalar parsing and lunge-speed division."""
import csv
import io
import struct
import unittest
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESI,UC_X86_REG_ESP
import test_melee_presentation_native as attacks

class DashMeleeMovementNativeTest(unittest.TestCase):
    def speed(self,row):
        parsed=attacks.MeleePresentationNativeTest().parse(row)
        duration=struct.unpack_from('<f',parsed,0x14)[0]
        distance=struct.unpack_from('<f',parsed,0x5c)[0]
        raw=(attacks.ROOT/'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u=Uc(UC_ARCH_X86,UC_MODE_32)
        u.mem_map(0x400000,(len(raw)+4095)&~4095);u.mem_write(0x400000,raw)
        u.mem_map(0x20000000,0x10000)
        move,stack,stub,value=0x20001000,0x20004000,0x20006000,0x20008000
        u.mem_write(move+0xaec,struct.pack('<f',duration))
        u.mem_write(value,struct.pack('<f',distance))
        u.mem_write(stub,b'\xd9\x05'+struct.pack('<I',value)+b'\xe9'+struct.pack('<i',0x4d9013-(stub+11)))
        u.reg_write(UC_X86_REG_ESI,move);u.reg_write(UC_X86_REG_ESP,stack)
        u.emu_start(stub,0x4d9024,count=100)
        return struct.unpack('<f',u.mem_read(move+0xa80,4))[0]

    def test_dash_has_forward_lunge_while_normal_remains_stationary(self):
        rows=list(csv.reader(io.StringIO(attacks.hangar_experiment.weapon_tables('item/wrestle.csv').decode())))[2:]
        for row in rows:
            with self.subTest(attack=row[0]):
                velocity=self.speed(row)
                if int(row[27])==36:
                    self.assertGreater(velocity,0,'zero CSV25 makes native lunge speed zero')
                else:self.assertEqual(velocity,0)

if __name__=='__main__':unittest.main()
