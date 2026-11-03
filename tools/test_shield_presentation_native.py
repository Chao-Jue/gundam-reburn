"""Shield presentation contract: native channel/class and skeleton compatibility.

Resource presence and matching bone names do not prove a correct rendered pose.
"""
import csv
import io
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment
import test_weapon_motion_class_native as motion_native


class ShieldPresentationNativeTest(unittest.TestCase):
    def shield(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        return next(r for r in rows if int(r[0]) == hangar_experiment.SHIELD_ITEM_ID), rows

    def test_shield_uses_a_separate_native_overlay_channel(self):
        shield, rows = self.shield()
        native = motion_native.MotionClassNativeTest()
        channel = native.native_layer(int(shield[14] or 0))
        self.assertEqual(channel, 2, 'channel0 disables shield; channel1 replaces weapon pose')
        for row in rows:
            if row is not shield:
                self.assertNotEqual(channel, native.native_layer(int(row[14] or 0)))
        self.assertEqual(int(shield[11]), 4, 'keep the current left-hand socket during pose trial')

    def test_selected_guard_pose_references_only_existing_gm_bones(self):
        shield, _ = self.shield()
        group = motion_native.MotionClassNativeTest().resolve(shield[15])
        assets = ROOT / 'GundamOnline_CHINA_已解密/decrypted'
        data = (assets / 'chara/01/01/0101/model/MSM_0101_0101_01.dxg').read_bytes()
        offset = 24 + struct.unpack_from('<I', data, 20)[0]
        bones = None
        while offset+8 <= len(data):
            kind, size = struct.unpack_from('<2I', data, offset)
            end = offset+8+size
            self.assertGreater(size, 0)
            self.assertLessEqual(end, len(data))
            if kind == 36:
                length = struct.unpack_from('<I', data, offset+8)[0]
                self.assertLessEqual(offset+12+length, end)
                bones = {s.decode('utf8') for s in data[offset+12:offset+12+length].split(b'\0') if s}
                break
            offset = end
        self.assertIsNotNone(bones)
        # This candidate's guarded stance is base101, as observed for class30.
        path = assets / f'chara/01/01/anim/MSA_0101_{group*1000+101:05d}.mrb'
        pose = path.read_bytes()
        self.assertEqual(pose[:8], b'MRB\0\0\0\1\0')
        first, second = struct.unpack_from('<2I', pose, 0x38)
        self.assertIn(1, (first, second))
        length = second if first == 1 else first
        self.assertLessEqual(0x40+length, len(pose))
        targets = {s.decode('utf8') for s in pose[0x40:0x40+length].split(b'\0') if s}
        self.assertTrue(targets)
        self.assertLessEqual(targets, bones, 'old pose references a different left-arm skeleton')
        self.assertFalse(any(s.startswith(('T_R_', 'T_L_Thigh', 'T_L_Knee', 'T_L_Foot'))
                             for s in targets), 'shield candidate must not animate gun arm or legs')
        self.assertIn('T_L_Hand', targets)


if __name__ == '__main__':
    unittest.main()
