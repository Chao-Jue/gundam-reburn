"""Execute CAtkParamTable scalar mapping, excluding strings/effects/rendering."""
import csv
import io
import struct
import sys
import unittest
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment


class MeleePresentationNativeTest(unittest.TestCase):
    def parse(self, row):
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0, 0x1000)
        u.mem_map(0x400000, (len(image)+4095)&~4095)
        u.mem_write(0x400000, image)
        u.mem_map(0x20000000, 0x10000)
        stack, output, stop, stub, scalar = 0x20008000, 0x20001000, 0x20009000, 0x2000a000, 0x2000b000
        u.mem_write(stack, struct.pack('<4I', stop, 0x20003000, 0, output))
        u.reg_write(UC_X86_REG_ESP, stack)

        def primitive(m, address, size, data):
            if address not in (0xb081e0, 0xb08260, 0xb082e0, 0x55bb80, 0x40ce60, 0x53dd00):
                return
            sp = m.reg_read(UC_X86_REG_ESP)
            ret = struct.unpack('<I', m.mem_read(sp, 4))[0]
            if address == 0x53dd00:
                # Enum lookup only; scalar offsets below execute native code.
                modes = {'': 0, 'NONE': 0, 'L_HAND': 1, 'R_HAND': 2, 'ACTIVE_WEAPON': 3}
                self.assertIn(row[17], modes)
                flags = struct.unpack('<I', m.mem_read(sp+8, 4))[0]
                m.mem_write(flags, bytes(4))
                m.reg_write(UC_X86_REG_EAX, modes[row[17]])
            elif address == 0x40ce60:
                left, right, count = struct.unpack('<3I', m.mem_read(sp+4, 12))
                a, b = bytes(m.mem_read(left, count)), bytes(m.mem_read(right, count))
                m.reg_write(UC_X86_REG_EAX, 0 if a == b else (1 if a > b else 0xffffffff))
            elif address in (0xb081e0, 0xb08260):
                column = struct.unpack('<I', m.mem_read(sp+8, 4))[0]
                value = row[column] or '0'
                if address == 0xb08260:
                    m.mem_write(scalar, struct.pack('<f', float(value)))
                    m.mem_write(stub, b'\xd9\x05'+struct.pack('<I', scalar)+b'\xc3')
                    m.reg_write(UC_X86_REG_EIP, stub)
                    return
                m.reg_write(UC_X86_REG_EAX, int(value)&0xffffffff)
            else:
                # Empty string/effect helpers only; no resource substitutions.
                if address == 0xb082e0:
                    column = struct.unpack('<I', m.mem_read(sp+12, 4))[0]
                    value = row[column].encode('ascii')
                    self.assertLess(len(value), 16)
                else:
                    self.assertEqual(row[28], '')
                dest = struct.unpack('<I', m.mem_read(sp+4, 4))[0]
                m.mem_write(dest, bytes(28))
                if address == 0xb082e0:
                    m.mem_write(dest+4, value+b'\0')
                    m.mem_write(dest+0x14, struct.pack('<I', len(value)))
                m.mem_write(dest+0x18, struct.pack('<I', 7 if address == 0x55bb80 else 15))
                m.reg_write(UC_X86_REG_EAX, dest)
            m.reg_write(UC_X86_REG_ESP, sp+4)
            m.reg_write(UC_X86_REG_EIP, ret)

        u.hook_add(UC_HOOK_CODE, primitive)
        u.emu_start(0x53deb0, stop, count=100000)
        self.assertEqual(u.reg_read(UC_X86_REG_EIP), stop)
        return bytes(u.mem_read(output, 0xa4))

    def test_generated_actions_have_native_duration_and_base_motion(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables('item/wrestle.csv').decode())))[2:]
        self.assertEqual({int(r[0]) for r in rows}, {880001, 880002, 880011, 880012})
        for row in rows:
            with self.subTest(action=row[0]):
                native = self.parse(row)
                self.assertEqual(struct.unpack_from('<I', native)[0], int(row[0]))
                dash = int(row[0]) in (880011, 880012)
                self.assertAlmostEqual(struct.unpack_from('<f', native, 0x14)[0], .366 if dash else .5)
                self.assertEqual(struct.unpack_from('<I', native, 0x64)[0], 36 if dash else 30)
                self.assertEqual(struct.unpack_from('<I', native, 0x10)[0], 0,
                                 'col5 is not the float duration at +14')


    def test_generated_melee_has_weapon_anchor_and_nonzero_collision_volume(self):
        rows=list(csv.reader(io.StringIO(hangar_experiment.weapon_tables('item/wrestle.csv').decode())))[2:]
        for row in rows:
            with self.subTest(action=row[0]):
                parsed=self.parse(row)
                with self.subTest(check='anchor'):
                    self.assertEqual(struct.unpack_from('<I',parsed,0x38)[0],3,
                                     'NONE falls back to body center instead of active saber')
                with self.subTest(check='volume'):
                    self.assertTrue(all(v>0 for v in struct.unpack_from('<3f',parsed,0x40)),
                                    'zero half extents cannot form a melee collision volume')


    def window_dispatch(self, start, end, elapsed):
        from unicorn.x86_const import UC_X86_REG_ESI, UC_X86_REG_EBX
        import test_projectile_presentation_native as machine
        u=machine.ProjectilePresentationNativeTest().machine()
        state=0x20001000
        u.mem_write(state+0xa3c,struct.pack('<2f',start,end))
        u.mem_write(state+0xa50,struct.pack('<2f',elapsed-.016,elapsed))
        u.reg_write(UC_X86_REG_ESI,state);u.reg_write(UC_X86_REG_EBX,0)
        reached=[]
        def stop(m,address,size,data):
            if address in (0x4bc77d,0x4bc87d):
                reached.append(address);m.emu_stop()
        u.hook_add(UC_HOOK_CODE,stop)
        u.emu_start(0x4bc743,0x4bc880,count=50)
        self.assertTrue(reached)
        return reached[0]==0x4bc77d

    def test_zero_window_skips_native_melee_scan(self):
        self.assertFalse(self.window_dispatch(0,0,.2))
        self.assertTrue(self.window_dispatch(.1,.35,.2))
        self.assertFalse(self.window_dispatch(.1,.35,.05))
        self.assertFalse(self.window_dispatch(.1,.35,.4))

    def test_generated_attack_event_has_live_collision_window(self):
        rows=list(csv.reader(io.StringIO(hangar_experiment.weapon_tables('item/wrestle.csv').decode())))[2:]
        for row in rows:
            with self.subTest(action=row[0]):
                data=self.parse(row)
                # A38FD0 event3 takes atk+24/+28 as window start/end.
                start,end=struct.unpack_from('<2f',data,0x24)
                duration=struct.unpack_from('<f',data,0x14)[0]
                self.assertTrue(self.window_dispatch(start,end,duration*.5),
                                'zero event window prevents 6338D0 collision scan')
                self.assertLessEqual(end,duration)


    def test_generated_melee_scans_from_swing_start_through_end(self):
        rows=list(csv.reader(io.StringIO(hangar_experiment.weapon_tables('item/wrestle.csv').decode())))[2:]
        for row in rows:
            data=self.parse(row)
            start,end=struct.unpack_from('<2f',data,0x24)
            duration=struct.unpack_from('<f',data,0x14)[0]
            for elapsed in (.01,duration*.5,duration-.01):
                with self.subTest(attack=row[0],elapsed=elapsed):
                    self.assertTrue(self.window_dispatch(start,end,elapsed),
                        'configured window drops early/late blade contact')

    def test_collision_box_covers_visible_saber_tip_in_weapon_local_space(self):
        # Read-only geometry proof: attached PP_02_001_01/saber_body uses
        # PM_02_001_01 (+X blade), anchored at hilt s_shot01.
        import math
        sys.path.insert(0,str(ROOT/'tools/model_matcher'))
        import dxg
        assets=ROOT/'GundamOnline_CHINA_已解密/decrypted'
        hilt=dxg.parse((assets/'item/04/0101/model/EM_04_0101_01.dxg').read_bytes())
        matrix=next(x['matrix'] for x in hilt['sockets'] if x['name']=='s_shot01')
        blade=dxg.parse((assets/'fx/02/model/PM_02_001_01.dxg').read_bytes())
        # Rotation about blade X preserves its length; cover the YZ envelope
        # over a full turn, plus the VRA's local Z=-10 translation.
        points=[]
        for mesh in blade['meshes']:
            p=mesh['positions']
            for i in range(0,len(p),3):
                radius=math.hypot(p[i+1],p[i+2])
                for y,z in ((radius,0),(-radius,0),(0,radius),(0,-radius)):
                    x=p[i];z-=10
                    points.append(tuple(x*matrix[j]+y*matrix[4+j]+z*matrix[8+j]+matrix[12+j] for j in range(3)))
        rows=list(csv.reader(io.StringIO(hangar_experiment.weapon_tables('item/wrestle.csv').decode())))[2:]
        for row in rows:
            with self.subTest(action=row[0]):
                parsed=self.parse(row)
                half=struct.unpack_from('<3f',parsed,0x40)
                center=struct.unpack_from('<3f',parsed,0x4c)
                self.assertTrue(all(abs(p[j]-center[j])<=half[j]+.001 for p in points for j in range(3)),
                                'visible beam blade extends outside the weapon-local damage box')
                self.assertLess(max(half),100,'avoid replacing blade reach with a broad body-area hitbox')
