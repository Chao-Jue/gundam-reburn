import os
import struct
import unittest
from unittest.mock import patch
import fake_auth


class ItemInitTest(unittest.TestCase):
    def decode(self, body):
        offset = 32
        groups = []
        for _ in range(4):
            count = struct.unpack_from('<I', body, offset)[0]
            offset += 4
            group = []
            for _ in range(count):
                group.append(struct.unpack_from('<QIIIH', body, offset))
                offset += 22
            groups.append(group)
        self.assertEqual(offset+16, len(body))
        return groups

    def test_hard_limit_survives_environment_override(self):
        items = [(i, 80100001, 777) for i in range(101)]
        for value, expected in [('100',100), ('101',100), ('999',100),
                                ('0',100), ('-1',100), ('bad',100), ('',100), ('5',5)]:
            with self.subTest(value=value), patch.dict(os.environ, {'MSGO_ITEM_MAX': value}):
                groups = self.decode(fake_auth.item_init_body(items))
                self.assertEqual([len(g) for g in groups], [expected,expected,0,0])
                self.assertEqual(groups[1][0][-1], 777)

    def test_default_debug_grant_and_empty_inventory_layout(self):
        with patch.dict(os.environ, {}, clear=True):
            op, body = fake_auth.hall_reply(0x947E, bytes(4), 'test')
            self.assertEqual(op, 0x02EE)
            self.assertEqual(len(body), 548)
            self.assertEqual([len(g) for g in self.decode(body)], [11,11,0,0])
            self.assertEqual(len(fake_auth.item_init_body([])), 64)
            for count in (99,100,101):
                groups = self.decode(fake_auth.item_init_body([(i,80100001,1) for i in range(count)]))
                self.assertEqual(len(groups[0]), min(count,100))
