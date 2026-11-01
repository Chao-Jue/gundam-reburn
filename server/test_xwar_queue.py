import struct
import unittest
from unittest.mock import patch

import fake_auth
import xwar_entry


class FormalBattleQueueTest(unittest.TestCase):
    def setUp(self):
        self.queue = xwar_entry.BookingQueue()
        self.request = struct.pack('<7I', 0, 4, 0, 0, 0, 0, 0)
        self.room = xwar_entry.BattleRoom(0, 1234, 10001, '127.0.0.1', 30100, 'test-ticket', 10)

    def test_unconfigured_backend_does_not_claim_match_or_publish_room(self):
        self.queue.register('a', 1, self.request, troops=0)
        self.assertEqual(self.queue.info_replies('a', 1, bytes(4)),
                         [(0xEA2C, struct.pack('<7I', 0, 0, 0, 1, 0, 0, 0))])
        reply = self.queue.enter('a', 1, struct.pack('<II', 0, 1234))
        self.assertEqual(struct.unpack_from('<I', reply)[0], 0xffffffff)
        self.assertNotIn(b'127.0.0.1', reply)

    def test_ready_room_notification_and_credentials_are_owner_scoped(self):
        self.queue.register('a', 1, self.request, troops=0)
        self.queue.register('b', 1, self.request, troops=1)
        self.queue.set_status(0, active=True, remaining_count=1, remaining_seconds=90)
        self.assertEqual(struct.unpack('<7I', self.queue.info_replies('b', 1, bytes(4))[0][1]),
                         (0, 1, 0, 1, 1, 1, 90))
        self.assertTrue(self.queue.assign_room('a', 1, self.room))
        self.assertFalse(self.queue.assign_room('missing', 1, self.room))
        replies = self.queue.info_replies('a', 1, bytes(4))
        self.assertEqual(replies, [(0xEA2C, struct.pack('<7I', 0, 1, 1, 0, 1, 1, 90)),
                                  (0xB099, struct.pack('<4I', 0, 1234, 10, 10001))])
        self.assertEqual(len(self.queue.info_replies('a', 1, bytes(4))), 1)
        self.assertEqual(len(self.queue.info_replies('b', 1, bytes(4))), 1)
        request = struct.pack('<II', 0, 1234)
        self.assertEqual(self.queue.enter('a', 1, request),
                         struct.pack('<II', 0, 0) + b'127.0.0.1\0' + struct.pack('<II', 30100, 1234) + b'test-ticket\0')
        self.assertEqual(struct.unpack_from('<I', self.queue.enter('b', 1, request))[0], 0xffffffff)
        self.assertEqual(struct.unpack_from('<I', self.queue.enter('a', 2, request))[0], 0xffffffff)
        self.assertEqual(struct.unpack_from('<I', self.queue.enter('a', 1, struct.pack('<II', 1, 1234)))[0], 0xffffffff)

    def test_cancel_revokes_room_and_reregister_is_idempotent(self):
        self.queue.register('a', 1, self.request)
        self.queue.assign_room('a', 1, self.room)
        self.queue.info_replies('a', 1, bytes(4))
        self.queue.register('a', 1, self.request)
        self.assertEqual(len(self.queue.info_replies('a', 1, bytes(4))), 1)
        self.assertEqual(self.queue.enter('a', 1, struct.pack('<II', 0, 1234)), self.room.enter_body())
        self.queue.cancel('a', 1, bytes(4))
        self.assertFalse(self.queue.rooms)
        self.assertFalse(self.queue.notified)
        self.assertEqual(struct.unpack_from('<I', self.queue.enter('a', 1, struct.pack('<II', 0, 1234)))[0], 0xffffffff)

    def test_bad_requests_and_room_metadata_do_not_allocate(self):
        self.assertEqual(self.queue.info_replies('a', 1, b''), [])
        self.assertIsNone(self.queue.enter('a', 1, bytes(7)))
        for kwargs in [dict(mission_id=xwar_entry.MISSION_ID), dict(host=''), dict(port=0),
                       dict(otp='a' * 41), dict(host='host\0injected')]:
            params = dict(matching=0, room_id=1, mission_id=2, host='localhost', port=30100, otp='abc')
            params.update(kwargs)
            with self.assertRaises(ValueError):
                xwar_entry.BattleRoom(**params)

    def test_hall_routes_formal_room_entry_and_preserves_normal_mode(self):
        request = struct.pack('<II', 0, 1234)
        self.queue.register('a', 1, self.request)
        self.queue.assign_room('a', 1, self.room)
        with patch.object(fake_auth, 'HANGAR_EXPERIMENT', True), patch.object(xwar_entry, 'BOOKINGS', self.queue):
            self.assertEqual(fake_auth.hall_replies(0x846A, request, 'a', 1), [(0x5383, self.room.enter_body())])
            self.assertIn(0x846A, fake_auth.HALL_OPS)
        with patch.object(fake_auth, 'HANGAR_EXPERIMENT', False):
            for opcode, body in [(0xFC4B, bytes(4)), (0x846A, request)]:
                self.assertEqual(fake_auth.hall_replies(opcode, body, 'a', 1), [])


if __name__ == '__main__':
    unittest.main()
