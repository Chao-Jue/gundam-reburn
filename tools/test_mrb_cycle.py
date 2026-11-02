import math
import struct
import unittest
from inspect_mrb_cycle import endpoints, compare, angle_degrees


def fixture():
    header = bytearray(0x40)
    header[:8] = b'MRB\0\0\0\1\0'
    struct.pack_into('<II', header, 0x38, 1, 4)
    s = math.sqrt(.5)
    return (bytes(header)+b'leg\0'+struct.pack('<6I', 2, 4, 0, 17, 1, 4)
            +struct.pack('<I', 200)+struct.pack('<II3f', 1, 12, 0, 0, 0)
            +struct.pack('<II8f', 2, 16, 0, 0, 0, 1, 0, 0, s, s)
            +struct.pack('<II3f', 1, 12, 1, 1, 1)
            +struct.pack('<II6H', 1, 12, 0, 0, 0, 0, 1, 0))


class MrbCycleTest(unittest.TestCase):
    def test_endpoint_continuity_uses_normalized_quaternions(self):
        value = endpoints(fixture())
        self.assertEqual(value['frames'], 2)
        self.assertEqual(value['ticks'], (0, 17))
        self.assertAlmostEqual(compare(value, value, ['leg'])['leg'], 90)
        a, b = value['rotations']['leg']
        reverse = {'rotations': {'leg': (b, a)}}
        self.assertAlmostEqual(compare(value, reverse, ['leg'])['leg'], 0)
        self.assertEqual(angle_degrees((0, 0, 0, 2), (0, 0, 0, -1)), 0)

    def test_truncation_trailing_data_and_bad_indices_are_rejected(self):
        raw = fixture()
        for bad in (raw[:-1], raw+b'\0', raw[:-6]+struct.pack('<3H', 99, 1, 0)):
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                endpoints(bad)

    def test_unknown_layout_and_zero_quaternion_are_rejected(self):
        with self.assertRaises(ValueError):
            endpoints(b'not an MRB')
        with self.assertRaises(ValueError):
            angle_degrees((0, 0, 0, 0), (0, 0, 0, 1))
