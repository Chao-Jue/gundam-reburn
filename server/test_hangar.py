import struct
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from hangar import HangarStore, unit_wire, unit_add_body, weapon_wire


def sample_unit():
    # Synthetic test IDs; not a claimed current-client/Wiki mapping.
    return {'uniqid': 1001, 'msma_id': 7, 'nickname': '测试机', 'blueprint_grade': 'silver',
            'cost': 200, 'equipped_weapons': [11, 0, 0],
            'weapons': [{'item_id': 11}, {'item_id': 12}]}


class HangarTest(unittest.TestCase):
    def test_change_persists_and_is_scoped_to_pilot(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'hangar.json'
            store = HangarStore(path)
            store.replace_units('a', 1, [sample_unit()])
            response = store.change_weapon('a', 1, struct.pack('<QHI', 1001, 2, 12))
            self.assertEqual(struct.unpack('<iQHI', response), (0, 1001, 2, 12))
            self.assertEqual(HangarStore(path).units('a', 1)[0]['equipped_weapons'], [11, 0, 12])
            self.assertEqual(store.units('a', 2), [])
            self.assertEqual(store.units('b', 1), [])
            before = path.read_bytes()
            for request in (b'', struct.pack('<QHI', 1001, 3, 12), struct.pack('<QHI', 1001, 0, 99)):
                with self.assertRaises(ValueError): store.change_weapon('a', 1, request)
            self.assertEqual(path.read_bytes(), before)

    def test_current_wire_sizes_and_fields(self):
        unit = sample_unit()
        data = unit_wire(unit)
        self.assertEqual(len(data), 299)
        self.assertEqual(struct.unpack_from('<Q', data)[0], 1001)
        self.assertEqual(struct.unpack_from('<I', data, 102)[0], 11)
        self.assertEqual(len(weapon_wire(unit['weapons'][0])), 30)
        self.assertEqual(len(unit_add_body(unit)), 299 + 4 + 60 + 4)

    def test_login_stream_contains_owned_unit_and_edit_reply(self):
        import fake_auth
        with tempfile.TemporaryDirectory() as folder:
            store = HangarStore(Path(folder) / 'hangar.json')
            store.replace_units('a', 2, [sample_unit()])
            with patch.object(fake_auth, 'HANGAR_STORE', store):
                messages = fake_auth.hall_replies(0x16AC, b'', 'a', 2)
                self.assertEqual([op for op, body in messages], [0x2ACF, 0xA832, 0xFCE6])
                self.assertEqual(messages[1][1], unit_add_body(sample_unit()))
                reply = fake_auth.hall_replies(0x0AA5, struct.pack('<QHI', 1001, 0, 12), 'a', 2)
                self.assertEqual(reply, [(0xD9DB, struct.pack('<iQHI', 0, 1001, 0, 12))])
                self.assertEqual(len(fake_auth.hall_replies(0x16AC, b'', 'a', 1)), 2)


if __name__ == '__main__':
    unittest.main()
