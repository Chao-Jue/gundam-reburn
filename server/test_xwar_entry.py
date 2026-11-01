import csv
import io
import struct
import unittest
from unittest.mock import Mock, patch
import fake_auth

class XwarEntryTest(unittest.TestCase):
    def test_experimental_register_calls_available_battle_backend(self):
        import xwar_entry
        queue = xwar_entry.BookingQueue()
        backend = Mock()
        record = struct.pack('<I', 77) + bytes(153)
        with patch.object(fake_auth, 'HANGAR_EXPERIMENT', True), patch.object(xwar_entry, 'BOOKINGS', queue), \
             patch.object(fake_auth, 'LOCAL_BATTLE', backend, create=True), \
             patch.object(fake_auth, 'saved_pilot_records', return_value={0: record, 1: None}):
            fake_auth.hall_replies(0x2EFF, struct.pack('<7I', 0, 4, 0, 0, 0, 0, 0), 'a', 77)
        backend.reserve.assert_called_once_with('a', 77, record)

    def test_booking_status_poll_is_answered(self):
        import xwar_entry
        queue = xwar_entry.BookingQueue()
        with patch.object(fake_auth, 'HANGAR_EXPERIMENT', True), patch.object(xwar_entry, 'BOOKINGS', queue):
            replies = fake_auth.hall_replies(0xFC4B, bytes(4), 'a', 1)
        self.assertEqual(replies, [(0xEA2C, struct.pack('<7I', 0, 0, 0, 0, 0, 0, 0))])
        self.assertIn(0xFC4B, fake_auth.HALL_OPS)

    def test_cancel_ack_has_current_native_8_byte_format(self):
        with patch.object(fake_auth, 'HANGAR_EXPERIMENT', True):
            reply = fake_auth.hall_replies(0xBEDC, struct.pack('<I', 0), 'cancel-test', 77)
        self.assertEqual(reply, [(0x736E, struct.pack('<II', 0, 0))])
        self.assertIn(0xBEDC, fake_auth.HALL_OPS)

    def test_pending_booking_is_scoped_idempotent_and_cancellable(self):
        import xwar_entry
        queue = xwar_entry.BookingQueue()
        body = struct.pack('<7I', 0, 4, 0, 0, 0, 0, 0)
        first = queue.register('a', 1, body)
        self.assertEqual(queue.register('a', 1, body), first)
        queue.register('a', 2, body)
        queue.register('b', 1, body)
        self.assertEqual(len(queue.pending), 3)
        queue.cancel('a', 1, struct.pack('<I', 8))
        self.assertEqual(len(queue.pending), 3)
        self.assertEqual(queue.cancel('a', 1, bytes(4)), struct.pack('<II', 0, 0))
        self.assertEqual(set(queue.pending), {('a', 2), ('b', 1)})
        before = dict(queue.pending)
        self.assertEqual(struct.unpack_from('<I', queue.register('a', 2, body[:-1]))[0], 0xffffffff)
        self.assertEqual(queue.pending, before)
        self.assertIsNone(queue.cancel('a', 2, b''))

    def test_experimental_scene_push_has_resolvable_vs_mission(self):
        with patch.object(fake_auth, 'HANGAR_EXPERIMENT', True):
            pushes = dict(fake_auth.hall_replies(0xC475, bytes(4), 'test'))
        self.assertIn(0xB080, pushes)
        import xwar_entry
        expected = struct.pack('<4I3B', 1, xwar_entry.MISSION_ID, 1, xwar_entry.MISSION_ID, 0, 0, 0)
        self.assertEqual(pushes[0xB080], expected)
        rows=list(csv.reader(io.StringIO(xwar_entry.table_body('mission/mission_vs.csv').decode())))[2:]
        self.assertEqual([int(r[0]) for r in rows], [xwar_entry.MISSION_ID, xwar_entry.PREPARATION_MISSION_ID])

    def test_booking_ack_has_current_native_25_byte_format(self):
        request=struct.pack('<7I',0,4,0,0,0,0,0)
        with patch.object(fake_auth,'HANGAR_EXPERIMENT',True):
            reply=fake_auth.hall_replies(0x2EFF,request,'booking-test',77)
        self.assertEqual([op for op,body in reply],[0xD52A])
        self.assertEqual(reply[0][1],struct.pack('<IIBIIIBHB',0,0,0,4,0,0,0,0,0))
        self.assertIn(0x2EFF,fake_auth.HALL_OPS)

    def test_normal_mode_does_not_advertise_test_battle(self):
        with patch.object(fake_auth,'HANGAR_EXPERIMENT',False):
            self.assertNotIn(0xB080,dict(fake_auth.hall_replies(0xC475,bytes(4),'test')))

if __name__=='__main__':unittest.main()
