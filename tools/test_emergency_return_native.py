"""Current client emergency-return reply and completion readers, without UI/render."""
import struct
import unittest
import csv
import io
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_ECX,UC_X86_REG_EAX,UC_X86_REG_EBP,UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EIP
import test_projectile_presentation_native as native
import hangar_experiment


class EmergencyReturnNativeTest(unittest.TestCase):
    def test_generated_gm_permits_native_ground_crouch_during_return_entry(self):
        row=next(r for r in csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_model.csv').decode()))
                 if r and r[0]==str(hangar_experiment.MODEL_ID))
        u=native.ProjectilePresentationNativeTest().machine()
        move,actor,model,physics,vtable=0x20000000,0x20001000,0x20002000,0x20003000,0x20004000
        stack,stop,stub=0x20008000,0x20009000,0x20009020
        def external(m,address,size,data):
            if address not in (0xb081e0,0x473700,0x474f10,0x473c80,0x472960):return
            sp=m.reg_read(UC_X86_REG_ESP);ret=struct.unpack('<I',m.mem_read(sp,4))[0]
            if address==0xb081e0:
                self.assertEqual(struct.unpack('<I',m.mem_read(sp+8,4))[0],44)
                value=int(row[44])
            else:value=0
            m.reg_write(UC_X86_REG_EAX,value);m.reg_write(UC_X86_REG_ESP,sp+4);m.reg_write(UC_X86_REG_EIP,ret)
        u.hook_add(UC_HOOK_CODE,external)
        u.reg_write(UC_X86_REG_ESP,stack);u.reg_write(UC_X86_REG_EBP,model)
        u.reg_write(UC_X86_REG_ESI,44);u.reg_write(UC_X86_REG_EDI,0x20006000)
        # Real CSV44 numeric read, bool conversion and model+108 store.
        u.emu_start(0x53fd36,0x53fd5e,count=100)
        u.mem_write(move,struct.pack('<I',vtable))
        u.mem_write(move+4,struct.pack('<I',actor));u.mem_write(move+0x14,struct.pack('<I',1))
        u.mem_write(actor+0x10,struct.pack('<I',model));u.mem_write(actor+0x30c,struct.pack('<I',physics))
        u.mem_write(physics+0x57,b'\x01');u.mem_write(stub,b'\x31\xc0\xc3')
        for offset in (0xf8,0x348):u.mem_write(vtable+offset,struct.pack('<I',stub))
        u.mem_write(stack,struct.pack('<I',stop));u.reg_write(UC_X86_REG_ESP,stack);u.reg_write(UC_X86_REG_ECX,move)
        u.emu_start(0x4cdc60,stop,count=1000)
        self.assertEqual(u.reg_read(UC_X86_REG_EAX)&255,1,
                         'CSV44=0 blocks the crouch requested by native return entry4C5AB0')

    def test_self_reappearance_updates_existing_native_snapshot_cache(self):
        u=native.ProjectilePresentationNativeTest().machine()
        cache,source,stack,stop=0x117d390,0x20001000,0x20008000,0x20009000
        u.mem_write(cache+0x8f00,struct.pack('<I',0))
        for position in ((235,5,145),(300,5,-125)):
            u.mem_write(source,struct.pack('<H3h',1,*position)+bytes(36))
            u.mem_write(stack,struct.pack('<II',stop,source))
            u.reg_write(UC_X86_REG_ESP,stack);u.reg_write(UC_X86_REG_ECX,cache)
            u.emu_start(0xa003b0,stop,count=10000)
            self.assertEqual(struct.unpack('<I',u.mem_read(cache+0x8f00,4))[0],1)
            self.assertEqual(struct.unpack('<3h',u.mem_read(cache+2,6)),position)

    def accepts(self,body,finish=False):
        u=native.ProjectilePresentationNativeTest().machine()
        stack,source,arena=0x20008000,0x20001000,0x20003000
        u.mem_write(source,body)
        u.mem_write(stack+0x14,struct.pack('<II',source,source+len(body)))
        u.mem_write(stack+(0x34 if finish else 0x10),struct.pack('<I',arena))
        start,success,failures=((0xa83bdb,0xa83c2d,(0xa83c0c,)) if finish else
            (0xa85544,0xa8560d,(0xa85573,0xa855fd)))
        reached=[]
        def stop(m,address,size,data):
            if address in (success,*failures):reached.append(address);m.emu_stop()
        u.hook_add(UC_HOOK_CODE,stop)
        u.emu_start(start,0xa85797,count=10000)
        self.assertTrue(reached)
        return reached[0]==success

    def test_reply_and_finish_have_exact_current_native_cursor(self):
        for finish,body in ((False,struct.pack('<iIHI',0,0,1,10000)),
                            (False,struct.pack('<iIHI',0,1,1,0)),
                            (True,struct.pack('<H',1))):
            self.assertTrue(self.accepts(body,finish))
            for end in range(len(body)):
                self.assertFalse(self.accepts(body[:end],finish))
            self.assertFalse(self.accepts(body+b'\0',finish))
