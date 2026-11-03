"""Regression for distinguishing a character controller from its render object."""
import unittest
import struct
import probe_battle_entities as probe


class Memory:
    def __init__(self, model=0x4000):
        self.words = {0x1280: 0x2000, 0x2014: 0x3000, 0x1124: model}

    def u32(self, address):
        return self.words.get(address)

    def read(self, address, size):
        return bytes(size) if address == 0x4000 else None


class BattleRenderProbeTest(unittest.TestCase):
    def test_selected_bone_rotations_require_verified_transform_getters(self):
        class BoneMemory(Memory):
            def __init__(self):
                super().__init__()
                self.words.update({0x4244: 0x5000, 0x424c: 2,
                                   0x5000: 0x6000, 0x5004: 0x7000,
                                   0x6000: 0x8000, 0x600c: 0, 0x6014: 9,
                                   0x7000: 0x9000, 0x700c: 0, 0x7014: 9,
                                   0x805c: 0x50f6d0, 0x8060: 0x50f700,
                                   0x905c: 0x123456, 0x9060: 0x123457})

            def read(self, address, size):
                values = {0x6018: b'T_R_Hand\0', 0x7018: b'C_Spine\0\0',
                          0x6054: struct.pack('<4f', 0, 0, 0, 1),
                          0x607c: struct.pack('<4f', 0, .6, 0, .8)}
                return values.get(address)

        bones = probe.aim_bone_rotations(BoneMemory(), 0x4000)
        self.assertEqual([b['name'] for b in bones], ['T_R_Hand', 'C_Spine'])
        self.assertEqual(bones[0]['local_rotation_xyzw'], [0, 0, 0, 1])
        self.assertAlmostEqual(bones[0]['world_rotation_xyzw'][1], .6, places=5)
        self.assertIsNone(bones[1]['local_rotation_xyzw'])
        self.assertIsNone(bones[1]['world_rotation_xyzw'])

    def test_aim_diagnostics_read_model_transforms_and_each_motion_layer(self):
        class AimMemory(Memory):
            def __init__(self):
                super().__init__()
                self.words.update({0x4000+0x354+i*0x160: motion
                                   for i, motion in enumerate((1, 3101, 0, 0))})

            def read(self, address, size):
                values = {0x4054: (0, .6, 0, .8), 0x407c: (0, .6, 0, .8),
                          0x1154: (.5, 0)}
                if address in values:
                    return struct.pack('<'+'f'*len(values[address]), *values[address])
                return super().read(address, size)

        value = probe.render_state(AimMemory(), 0x1000)
        self.assertAlmostEqual(value['local_rotation_xyzw'][1], .6, places=5)
        self.assertAlmostEqual(value['world_rotation_xyzw'][3], .8, places=5)
        self.assertEqual(value['motion_layers'], [1, 3101, 0, 0])
        self.assertEqual(value['weapon_pose_hold_seconds'], [.5, 0])

    def test_controller_does_not_count_as_a_render_object(self):
        value = probe.render_state(Memory(), 0x1000)
        self.assertEqual(value['controller'], 0x2000)
        self.assertEqual(value['render_object'], 0x4000)
        self.assertIsNotNone(value['render_raw'])

    def test_missing_render_object_is_reported_even_with_controller(self):
        value = probe.render_state(Memory(model=0), 0x1000)
        self.assertEqual(value['controller'], 0x2000)
        self.assertEqual(value['render_object'], 0)
        self.assertIsNone(value['render_raw'])
        self.assertIsNone(value['local_rotation_xyzw'])
        self.assertIsNone(value['world_rotation_xyzw'])
        self.assertIsNone(value['motion_layers'])


if __name__ == '__main__':
    unittest.main()
