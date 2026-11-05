"""Native deployment-stage gate for releasing the joint aiming controller."""
import struct
import unittest
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EAX, UC_X86_REG_EIP
import test_projectile_presentation_native as native


class DeploymentAimNativeTest(unittest.TestCase):
    def test_native_zero_countdown_advances_stage_before_selection_is_closed(self):
        # Original failure: success closes the task before it can observe zero.
        # Execute the actual countdown receiver, selection callback and gate.
        for close_early, expected_stage in ((True,1),(False,3)):
            u=native.ProjectilePresentationNativeTest().machine()
            game,scene,task,params=0x21000000,0x20002000,0x20003000,0x20004000
            stack,stop=0x20008000,0x20009000
            u.mem_map(game,0x40000)
            u.mem_write(0x1161f28,struct.pack('<I',game))
            u.mem_write(0x1161f78,struct.pack('<I',scene))
            u.mem_write(scene+0x128,struct.pack('<I',1))
            u.mem_write(scene+0x100,struct.pack('<f',60))
            u.mem_write(task+4,struct.pack('<I',1))
            u.mem_write(task+0x14,struct.pack('<I',params))
            # Native pre-initBattle condition;6326E0 later clears this bit.
            u.mem_write(game+0x10a34,b'\x04')
            def external(m,address,size,data):
                if address not in (0x621e30,0x566ea0):return
                sp=m.reg_read(UC_X86_REG_ESP)
                ret=struct.unpack('<I',m.mem_read(sp,4))[0]
                m.reg_write(UC_X86_REG_EAX,0)
                m.reg_write(UC_X86_REG_ESP,sp+(12 if address==0x621e30 else 4))
                m.reg_write(UC_X86_REG_EIP,ret)
            u.hook_add(UC_HOOK_CODE,external)
            if close_early:
                u.mem_write(stack,struct.pack('<II',stop,0))
                u.reg_write(UC_X86_REG_ESP,stack);u.reg_write(UC_X86_REG_ECX,task)
                u.emu_start(0x4406a0,stop,count=100)
            u.mem_write(stack,struct.pack('<10I',stop,*([0]*9)))
            u.reg_write(UC_X86_REG_ESP,stack);u.reg_write(UC_X86_REG_ECX,game)
            u.emu_start(0x4407e0,stop,count=1000)
            self.assertEqual(struct.unpack('<f',u.mem_read(scene+0x100,4))[0],0)
            u.mem_write(stack,struct.pack('<I',stop))
            u.reg_write(UC_X86_REG_ESP,stack);u.reg_write(UC_X86_REG_ECX,task)
            if close_early:
                u.emu_start(0x4474e0,stop,count=2000)
            else:
                # State1's exact native stage check, ending immediately after
                # its optional store; later UI/resource actions are irrelevant.
                u.emu_start(0x447700,0x447733,count=1000)
            self.assertEqual(struct.unpack('<I',u.mem_read(scene+0x128,4))[0],expected_stage)

    def test_native_release_requires_finished_selection_stage(self):
        for stage, paused in ((1,1),(2,1),(0,0),(3,0)):
            with self.subTest(stage=stage):
                u=native.ProjectilePresentationNativeTest().machine()
                controller,joint,scene,stack,stop=0x20000000,0x20001000,0x20002000,0x20008000,0x20009000
                u.mem_write(0x1161f78,struct.pack('<I',scene))
                u.mem_write(controller+0x1c,struct.pack('<I',joint))
                u.mem_write(controller+0x24,b'\x01')
                u.mem_write(joint+0xcd,b'\x01')
                u.mem_write(scene+0x128,struct.pack('<I',stage))
                u.mem_write(scene+0x284,b'\x55\0')
                u.mem_write(stack,struct.pack('<If',stop,1/60))
                u.reg_write(UC_X86_REG_ESP,stack);u.reg_write(UC_X86_REG_ECX,controller)
                def external(m,address,size,data):
                    if address != 0x4b2120: return
                    sp=m.reg_read(UC_X86_REG_ESP)
                    ret=struct.unpack('<I',m.mem_read(sp,4))[0]
                    m.reg_write(UC_X86_REG_ESP,sp+8)
                    m.reg_write(UC_X86_REG_EIP,ret)
                u.hook_add(UC_HOOK_CODE,external)
                # Execute the real stage gate,61F9A0 and50AAA0 setter;
                # only unrelated skeleton animation update is replaced.
                u.emu_start(0x4b2480,stop,count=1000)
                self.assertEqual(bytes(u.mem_read(joint+0xcd,1)),bytes([paused]))
                self.assertEqual(bytes(u.mem_read(controller+0x24,1)),bytes([paused]))
