"""Regression of 0x7A68BB with native enum and ticket tree lookup."""
import csv
import io
from pathlib import Path
import struct
import sys
import unittest
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UcError
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment as experiment

def native_ticket_key(text):
    image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
    machine = Uc(UC_ARCH_X86, UC_MODE_32)
    machine.mem_map(0x400000, (len(image)+4095)&~4095)
    machine.mem_write(0x400000,image)
    machine.mem_map(0,0x1000)  # FS exception chain, no live process involved
    machine.mem_map(0x20000000,0x20000)
    sp,end,heap=0x20010000,0x20018000,0x20001000
    value=text.encode('ascii')
    record=bytearray(32)
    struct.pack_into('<I',record,0,end)
    if len(value)<16:
        record[8:8+len(value)]=value
    else:
        struct.pack_into('<I',record,8,heap)
        machine.mem_write(heap,value+b'\0')
    struct.pack_into('<II',record,24,len(value),max(15,len(value)))
    machine.mem_write(sp,bytes(record))
    machine.reg_write(UC_X86_REG_ESP,sp)
    def skip_free(m,address,size,data):
        if address==0xc11ccd:
            p=m.reg_read(UC_X86_REG_ESP)
            ret=struct.unpack('<I',m.mem_read(p,4))[0]
            m.reg_write(UC_X86_REG_ESP,p+4)
            m.reg_write(UC_X86_REG_EIP,ret)
    machine.hook_add(UC_HOOK_CODE,skip_free)
    machine.emu_start(0x548ad0,end,count=10000)
    if machine.reg_read(UC_X86_REG_EIP)!=end:raise AssertionError('enum did not return')
    return machine.reg_read(UC_X86_REG_EAX)

class WeaponDetailNativeTest(unittest.TestCase):
    def test_real_enum_distinguishes_numeric_text_and_ticket_name(self):
        self.assertEqual(native_ticket_key('2'),0)
        self.assertEqual(native_ticket_key('BUILDUP_GREATEST'),2)

    def test_selected_power_detail_has_required_ticket_record(self):
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000, (len(image)+4095)&~4095)
        u.mem_write(0x400000,image)
        u.mem_map(0x20000000,0x20000)
        owned,item,weapon,build,tickets,bnode,tnode,sp = [0x20001000+i*0x1000 for i in range(8)]
        u.mem_write(owned,struct.pack('<I',item))
        u.mem_write(item+0x4c,struct.pack('<I',weapon))
        u.mem_write(0x1169560,struct.pack('<I',build))
        u.mem_write(0x1169a00,struct.pack('<I',tickets))
        sentinel=0x20011000
        u.mem_write(tickets+8,struct.pack('<I',sentinel))
        # 1169A00 ctor 9BF9A0 -> DF89FC RTTI CMechanicWeaponTable.
        # Download enum19 MECHANIC_WEAPON -> mechanic_weapon.csv, not ticket.csv.
        body=experiment.table_body('develop/mechanic_weapon.csv')
        rows=list(csv.reader(io.StringIO(body.decode())))[2:] if body else []
        row=next((r for r in rows if native_ticket_key(r[0])==2),None)
        u.mem_write(sentinel,struct.pack('<III',sentinel,tnode if row else sentinel,sentinel))
        u.mem_write(sentinel+0x61,b'\x01')
        if row:
            u.mem_write(tnode,struct.pack('<IIII',sentinel,sentinel,sentinel,2))
            for i in range(10):
                u.mem_write(tnode+0x10+i*4,struct.pack('<I',int(row[1+2*i])*10))
                u.mem_write(tnode+0x38+i*4,struct.pack('<I',int(row[2+2*i])*10))
        u.mem_write(sp,struct.pack('<IIII',0x20018000,owned,0,0))
        u.reg_write(UC_X86_REG_ESP,sp)
        def hook(m,a,size,data):
            if a!=0x49f450:return
            p=m.reg_read(UC_X86_REG_ESP)
            ret,out,key=struct.unpack('<III',m.mem_read(p,12))
            value=bnode
            m.mem_write(out,struct.pack('<I',value))
            m.reg_write(UC_X86_REG_ESP,p+12)
            m.reg_write(UC_X86_REG_EIP,ret)
        u.hook_add(UC_HOOK_CODE,hook)
        try:
            u.emu_start(0x7a6810,0x20018000,count=5000)
        except UcError:
            self.assertEqual(u.reg_read(UC_X86_REG_EIP),0x7a68bb)
            raise
        self.assertEqual(u.reg_read(UC_X86_REG_EIP),0x20018000)
        self.assertIsNotNone(row)
if __name__=='__main__':unittest.main()
