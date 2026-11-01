"""Native description dereference regression; mission lookup is substituted."""
import csv
import io
from pathlib import Path
import struct
import sys
import unittest
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_ESI,UC_X86_REG_EIP
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'server'))
import xwar_entry

class XwarDescriptionNativeTest(unittest.TestCase):
    def run_native(self,selected):
        image=(ROOT/'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u=Uc(UC_ARCH_X86,UC_MODE_32)
        u.mem_map(0x400000,(len(image)+4095)&~4095)
        u.mem_write(0x400000,image)
        u.mem_map(0x20000000,0x10000)
        sp,window,mission=0x20008000,0x20001000,0x20002000
        u.reg_write(UC_X86_REG_ESP,sp)
        u.reg_write(UC_X86_REG_ESI,window)
        u.mem_write(sp+0xa0,struct.pack('<I',mission if selected else 0))
        if selected:
            row=list(csv.reader(io.StringIO(xwar_entry.table_body('mission/mission_vs.csv').decode())))[2]
            u.mem_write(mission+4,struct.pack('<I',int(row[0])))
        try:
            u.emu_start(0x737121,0x737148,count=30)
        except UcError:
            self.assertEqual(u.reg_read(UC_X86_REG_EIP),0x737130)
            raise
        return struct.unpack('<I',u.mem_read(window+0x1a0,4))[0]

    def test_old_missing_selection_reproduces_exact_fault(self):
        with self.assertRaises(UcError):self.run_native(False)

    def test_advertised_mission_is_read_by_native_description(self):
        self.assertEqual(self.run_native(True),xwar_entry.MISSION_ID)

if __name__=='__main__':unittest.main()
