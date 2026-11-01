"""Offline execution of actual client code, not a second Python decoder."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
from hangar import unit_wire, weapon_wire
from emulate_wire_reader import decode


class NativeReaderTest(unittest.TestCase):
    def test_unit_fields_and_truncation_using_current_exe_reader(self):
        record = unit_wire({'uniqid': 0x1234567812345678, 'msma_id': 7,
                            'nickname': '测试', 'cost': 200,
                            'equipped_weapons': [11, 12, 0], 'buildup_count': 9})
        ok, consumed, output = decode(0xA96070, record)
        self.assertEqual((ok, consumed), (1, 299))
        self.assertEqual(struct.unpack_from('<Q', output)[0], 0x1234567812345678)
        self.assertEqual(struct.unpack_from('<I', output, 8)[0], 7)
        self.assertEqual(struct.unpack_from('<3I', output, 0x6C), (11, 12, 0))
        self.assertEqual(struct.unpack_from('<H', output, 0xC4)[0], 9)
        self.assertEqual(decode(0xA96070, record[:-1])[0], 0)

    def test_weapon_fields_using_current_exe_reader(self):
        record = weapon_wire({'item_id': 11, 'db_index': 2, 'buildup_values': list(range(10))})
        ok, consumed, output = decode(0xA964D0, record)
        self.assertEqual((ok, consumed), (1, 30))
        self.assertEqual(struct.unpack_from('<IHH10H', output), (11, 2, 0, *range(10)))
        self.assertEqual(decode(0xA964D0, record[:-1])[0], 0)


if __name__ == '__main__':
    unittest.main()
