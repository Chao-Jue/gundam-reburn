"""Execute current client reaction readers and native motion selectors offline."""
import struct
import unittest
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ESP, UC_X86_REG_ECX
import test_projectile_presentation_native as native
import down_points
import battle_entities
import training_target


class DownPointsNativeTest(unittest.TestCase):
    def test_training_target_appearance_enables_native_snapshot_cache(self):
        body=battle_entities.appear_body(bytes(175),200,(12000,-2600,18000),
            team=1,troops=1,world_id=0,pilot_id=0,letter=255, snapshots=True)
        machine=native.ProjectilePresentationNativeTest().machine()
        out,snapshot,stack,stop=0x117d390,0x2000a000,0x2000b000,0x2000f000
        machine.mem_write(out+0x8f00,bytes(4))
        machine.mem_write(snapshot,struct.pack('<H',200)+bytes(42))
        args=[0]*14;args[5]=snapshot;args[11]=body[-3]
        machine.mem_write(stack,struct.pack('<I14I',stop,*args))
        machine.reg_write(UC_X86_REG_ESP,stack);machine.reg_write(UC_X86_REG_ECX,out)
        def skip_ui(m,address,size,data):
            if address==0xa554d0:m.emu_stop()
        machine.hook_add(UC_HOOK_CODE,skip_ui)
        machine.emu_start(0xaf47c0,stop,count=20000)
        self.assertEqual(struct.unpack('<I',machine.mem_read(out+0x8f00,4))[0],1)
        self.assertEqual(struct.unpack('<H',machine.mem_read(out,2))[0],200)

    def test_recovery_delta_marks_dirty_and_clears_native_cached_tumble_bits(self):
        body = training_target.recovery_delta(1)
        machine = native.ProjectilePresentationNativeTest().machine()
        out, arrays, stack, stop = 0x20000000,0x2000a000,0x2000b000,0x2000f000
        machine.mem_write(out,struct.pack('<H',200))
        machine.mem_write(out+36,struct.pack('<I',4))
        machine.mem_write(out+0x8f00,struct.pack('<I',1))
        args=[]; cursor=8
        for index in range(31):
            count=struct.unpack_from('<I',body,cursor)[0]; cursor+=4
            width=2 if index in (0,1) else 1
            pointer=arrays+index*16
            if count: machine.mem_write(pointer,body[cursor:cursor+count*width])
            cursor+=count*width;args.extend((pointer,count))
        self.assertEqual(cursor,len(body))
        machine.mem_write(stack,struct.pack('<I62I',stop,*args))
        machine.reg_write(UC_X86_REG_ESP,stack);machine.reg_write(UC_X86_REG_ECX,out)
        machine.emu_start(0x9ffb00,stop,count=20000)
        self.assertEqual(struct.unpack('<H',machine.mem_read(out+42,2))[0],0x20)
        self.assertEqual(struct.unpack('<I',machine.mem_read(out+36,4))[0],0)

    def test_recovery_snapshot_complete_native_reader(self):
        body = struct.pack('<III', 1, 0, 1)+battle_entities.snapshot_body(200, (12000,-2600,18000))
        for candidate, expected in ((body, True), (body[:-1], False), (body+b'\0', False)):
            machine = native.ProjectilePresentationNativeTest().machine()
            stack, source, arena = 0x20008000, 0x20001000, 0x20003000
            machine.mem_write(source, candidate)
            machine.mem_write(stack+0x14, struct.pack('<II',source,source+len(candidate)))
            machine.mem_write(stack+0x10, struct.pack('<I',arena))
            reached=[]
            def stop(m, address, size, data):
                if address in (0xa6e674,0xa6e588,0xa6e5db,0xa6e644,0xa6e65d):
                    reached.append(address);m.emu_stop()
            machine.hook_add(UC_HOOK_CODE,stop)
            machine.emu_start(0xa6e559,0xa85797,count=10000)
            self.assertTrue(reached)
            self.assertEqual(reached[0]==0xa6e674,expected)

    def parse(self, reaction, body):
        machine = native.ProjectilePresentationNativeTest().machine()
        stack, source, arena = 0x20008000, 0x20003000, 0x20004000
        machine.mem_write(source, body)
        machine.mem_write(stack+0x14, struct.pack('<II', source, source+len(body)))
        machine.mem_write(stack+0x40, struct.pack('<I', arena))
        start, success, failures = {
            'tumble': (0xa7bb02, 0xa7bc33, (0xa7bb31, 0xa7bc19)),
            'kneel': (0xa82ea6, 0xa82fd7, (0xa82ed5, 0xa82fbd)),
            'flinch': (0xa6b9b5, 0xa6bae6, (0xa6b9e4, 0xa6bacc)),
        }[reaction]
        reached = []
        def stop(m, address, size, data):
            if address in (success, *failures):
                reached.append(address)
                m.emu_stop()
        machine.hook_add(UC_HOOK_CODE, stop)
        machine.emu_start(start, 0xa85797, count=10000)
        self.assertTrue(reached)
        return reached[0] == success, bytes(machine.mem_read(arena, len(body)))

    def test_generated_reaction_fields_have_exact_native_cursor_and_values(self):
        for reaction in ('flinch', 'kneel', 'tumble'):
            with self.subTest(reaction=reaction):
                _, body = down_points.reaction_packet(reaction, 200, 65535)
                self.assertEqual(len(body), 14)
                self.assertEqual(self.parse(reaction, body), (True, body))
                for end in range(len(body)):
                    self.assertFalse(self.parse(reaction, body[:end])[0])
                self.assertFalse(self.parse(reaction, body+b'\0')[0])

    def test_native_short_hit_and_kneel_motion_groups_are_distinct(self):
        # 45FC -> state1000 -> selector+3BC: base19; E332 ->
        # state2000 -> selector+3B0: base71. Do not infer from English names.
        for address, expected in ((0x4cd020, 19), (0x4ccfc0, 71)):
            for alternate, offset in ((0, 0), (1, 200)):
                machine = native.ProjectilePresentationNativeTest().machine()
                machine.mem_write(0x20008000, struct.pack('<II', 0x20009000, alternate))
                machine.emu_start(address, 0x20009000, count=100)
                self.assertEqual(machine.reg_read(UC_X86_REG_EAX), expected+offset)
