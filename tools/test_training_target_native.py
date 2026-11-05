"""Current native appearance/hit packet readers, excluding render/AI callbacks."""
import struct
import unittest
from unicorn import UC_HOOK_CODE
import test_projectile_presentation_native as native
import test_battle_entities_native as entities_native
import training_target
import local_battle
import battle_entities


class TrainingTargetNativeTest(unittest.TestCase):
    def parse(self, body, hp):
        u = native.ProjectilePresentationNativeTest().machine()
        stack, source, arena = 0x20008000, 0x20003000, 0x20004000
        u.mem_write(source, body)
        u.mem_write(stack+0x14, struct.pack('<2I', source, source+len(body)))
        u.mem_write(stack+(0x34 if hp == 'show' else 0x20 if hp else 0x40), struct.pack('<I', arena))
        start, success, failures = ((0xa6c181, 0xa6c41a, (0xa6c1b0, 0xa6c400)) if hp else
                                    (0xa819eb, 0xa81b1c, (0xa81a1a, 0xa81b02)))
        if hp == 'show':
            start, success, failures = 0xa8321b, 0xa8338c, (0xa8323c, 0xa832a5, 0xa832c8, 0xa83334, 0xa83375)
        reached = []
        def stop(m, address, size, data):
            if address in (success, *failures):
                reached.append(address)
                m.emu_stop()
        u.hook_add(UC_HOOK_CODE, stop)
        u.emu_start(start, 0xa85797, count=10000)
        self.assertTrue(reached)
        return reached[0] == success

    def test_training_target_uses_complete_native_enemy_appearance(self):
        body = battle_entities.appear_body(local_battle.spawn_unit_body(training_target.UNIT, 255),
                200, (12445, -671, 16881), team=1, troops=1, world_id=0, pilot_id=0, letter=255)
        self.assertEqual(entities_native.EntityWireNativeTest().parse(body, False), (True, len(body)))

    def test_hit_feedback_and_hp_update_have_full_native_cursor(self):
        feedback = struct.pack('<I5H', 777108, 200, 0, 100, 65526, 150)
        hp = struct.pack('<HHIB4I6HI', 200, 1, 777108, 0, 3325, 3425, 100, 0,
                         100, 65526, 150, 0, 0, 0, 0)
        for body, mode in ((feedback, False), (hp, True)):
            self.assertTrue(self.parse(body, mode))
            self.assertFalse(self.parse(body[:-1], mode))
            self.assertFalse(self.parse(body+b'\0', mode))

    def test_hp_display_initialization_has_full_native_array_cursor(self):
        body = training_target.hp_display_body()
        self.assertTrue(self.parse(body, 'show'))
        self.assertFalse(self.parse(body[:-1], 'show'))
        self.assertFalse(self.parse(body+b'\0', 'show'))


class TargetAimHeightNativeTest(unittest.TestCase):
    def aim_height(self, height):
        from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_ECX,
                                       UC_X86_REG_ESP, UC_X86_REG_EIP)
        u = native.ProjectilePresentationNativeTest().machine()
        actor, table, node, sentinel = 0x20001000, 0x20002000, 0x20003000, 0x20004000
        stack, stop, result = 0x20008000, 0x20009000, 0x2000a000
        u.mem_write(0x11692dc, struct.pack('<I', table))
        u.mem_write(table+8, struct.pack('<I', sentinel))
        if height is not None:
            # 53FA30 CSV2 -> model+8; tree node data starts at +10.
            u.mem_write(node+0x18, struct.pack('<f', height))
        def lookup(m, address, size, data):
            if address != 0x47b460:
                return
            sp = m.reg_read(UC_X86_REG_ESP)
            ret, out, key = struct.unpack('<3I', m.mem_read(sp, 12))
            self.assertEqual(m.reg_read(UC_X86_REG_ECX), table+4)
            m.mem_write(out, struct.pack('<I', sentinel if height is None else node))
            m.reg_write(UC_X86_REG_EAX, out)
            m.reg_write(UC_X86_REG_ESP, sp+12)
            m.reg_write(UC_X86_REG_EIP, ret)
        u.hook_add(UC_HOOK_CODE, lookup)
        u.mem_write(stack, struct.pack('<I', stop))
        u.mem_write(stop, b'\xd9\x1d'+struct.pack('<I', result))
        u.reg_write(UC_X86_REG_ESP, stack)
        u.reg_write(UC_X86_REG_ECX, actor)
        u.emu_start(0x47eae0, stop+6, count=1000)
        return struct.unpack('<f', u.mem_read(result, 4))[0]

    def test_native_placeholder_centers_aim_at_feet_and_default_is_eighty(self):
        self.assertEqual(self.aim_height(1), 1)
        self.assertEqual(self.aim_height(None), 80)

    def test_generated_gm_aim_center_uses_native_fallback_height(self):
        import csv, io, hangar_experiment
        row = next(r for r in csv.reader(io.StringIO(
            hangar_experiment.table_body('msma/msma_model.csv').decode()))
            if r and r[0] == str(hangar_experiment.MODEL_ID))
        self.assertEqual(self.aim_height(float(row[2])), self.aim_height(None),
                         'diagnostic height 1 puts the aim/lock center at the feet')



class TargetMeleeGateNativeTest(unittest.TestCase):
    def geometry_gate(self, value):
        from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBP,
            UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBX,
            UC_X86_REG_ESP, UC_X86_REG_EIP)
        u = native.ProjectilePresentationNativeTest().machine()
        model, actor = 0x20001000, 0x20002000
        u.reg_write(UC_X86_REG_EBP, model)
        u.reg_write(UC_X86_REG_ESI, 48)
        u.reg_write(UC_X86_REG_EDI, 0x20003000)
        def integer(m, address, size, data):
            if address != 0xb081e0: return
            sp = m.reg_read(UC_X86_REG_ESP)
            ret, source, col = struct.unpack('<3I', m.mem_read(sp,12))
            self.assertEqual(col,48)
            m.reg_write(UC_X86_REG_EAX, int(value or 0))
            m.reg_write(UC_X86_REG_ESP,sp+4)
            m.reg_write(UC_X86_REG_EIP,ret)
        h = u.hook_add(UC_HOOK_CODE,integer)
        u.emu_start(0x53fd96,0x53fdbe,count=100)
        u.hook_del(h)
        u.mem_write(actor+0x10,struct.pack('<I',model))
        u.reg_write(UC_X86_REG_EBX,actor)
        reached=[]
        def stop(m,address,size,data):
            if address in (0x633cb7,0x633d47):
                reached.append(address);m.emu_stop()
        u.hook_add(UC_HOOK_CODE,stop)
        u.emu_start(0x633ca7,0x633d48,count=20)
        self.assertTrue(reached)
        return reached[0]==0x633cb7

    def test_native_disabled_model_skips_melee_geometry_collection(self):
        self.assertFalse(self.geometry_gate(0))
        self.assertTrue(self.geometry_gate(1))

    def test_generated_gm_allows_native_melee_geometry_collection(self):
        import csv,io,hangar_experiment
        row=next(r for r in csv.reader(io.StringIO(
            hangar_experiment.table_body('msma/msma_model.csv').decode()))
            if r and r[0]==str(hangar_experiment.MODEL_ID))
        self.assertTrue(self.geometry_gate(row[48] if len(row)>48 else 0),
                        'missing model CSV48 skips every target collision shape')
