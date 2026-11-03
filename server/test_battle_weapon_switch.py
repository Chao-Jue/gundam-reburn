import struct
import unittest
import local_battle
import xwar_entry


class BattleWeaponSwitchTest(unittest.TestCase):
    def setUp(self):
        queue = xwar_entry.BookingQueue()
        queue.register('test', 77, struct.pack('<7I', 0, 4, 0, 0, 0, 0, 0))
        self.backend = local_battle.LocalBattleBackend(queue, '127.0.0.1', 30000)
        self.room = self.backend.reserve('test', 77, struct.pack('<I', 77)+bytes(153))
        self.room.round_active = self.room.entities_ready = True
        self.room.spawned_weapon_ids = (777108, 777106, 777103)

    def request(self, index, ai=0):
        return self.backend.replies(self.room, 0xea5a, struct.pack('<IBH', 0, index, ai))

    def test_grenade_release_has_owned_item_and_unique_presentation_identity(self):
        self.request(2)
        body = struct.pack('<I8HBBIBHB', 0, 124, 65521, 147, 93, 65527, 165,
                           0, 0, 0, 0, 0, 0, 0, 255)
        replies = [self.backend.replies(self.room, 0x7c0c, body) for _ in range(2)]
        for index, reply in enumerate(replies, 1):
            self.assertEqual(reply, [(0x1a13, struct.pack('<HII8H3B', 1, 777103, index,
                             124, 65521, 147, 93, 65527, 165, 0, 1500, 0, 0, 0))])
        for invalid in (body[:-1], body+b'\0', body[:20]+b'\x01'+body[21:]):
            self.assertEqual(self.backend.replies(self.room, 0x7c0c, invalid), [])
        fields = list(struct.unpack('<I8HBBIBHB', body))
        for field, invalid_value in ((7, 100), (8, 10001), (10, 1), (11, 1), (12, 1), (13, 100), (14, 2)):
            invalid = fields.copy()
            invalid[field] = invalid_value
            self.assertEqual(self.backend.replies(self.room, 0x7c0c,
                             struct.pack('<I8HBBIBHB', *invalid)), [])
        self.room.entities_ready = False
        self.assertEqual(self.backend.replies(self.room, 0x7c0c, body), [])
        self.room.entities_ready = True
        self.request(0)
        self.assertEqual(self.backend.replies(self.room, 0x7c0c, body), [])

    def test_grenade_impact_is_once_for_an_issued_grenade_even_after_switch(self):
        self.request(2)
        release = struct.pack('<I8HBBIBHB', 0, 124, 65521, 147, 93, 65527, 165,
                              0, 0, 0, 0, 0, 0, 0, 255)
        self.backend.replies(self.room, 0x7c0c, release)
        self.request(0)
        fields = [0, 105, 65520, 160, 105, 65520, 160, 0, 0, 1, 0, 1, 0, 0, 255]
        impact = struct.pack('<I8HBBIBHB', *fields)
        for field, value in ((9, 2), (10, 1), (11, 999), (12, 1), (13, 100), (7, 100)):
            invalid = fields.copy()
            invalid[field] = value
            self.assertEqual(self.backend.replies(self.room, 0x7c0c,
                             struct.pack('<I8HBBIBHB', *invalid)), [])
        self.assertEqual(self.backend.replies(self.room, 0x7c0c, impact),
                         [(0x1a13, struct.pack('<HII8H3B', 1, 777103, 1,
                          105, 65520, 160, 105, 65520, 160, 0, 0, 1, 0, 0))])
        self.assertEqual(self.backend.replies(self.room, 0x7c0c, impact), [])

    def test_grenade_pending_presentations_are_bounded_and_expire(self):
        self.request(2)
        now = self.backend.clock()
        self.backend.clock = lambda: now
        release = struct.pack('<I8HBBIBHB', 0, 124, 65521, 147, 93, 65527, 165,
                              0, 0, 0, 0, 0, 0, 0, 255)
        for _ in range(64):
            self.assertTrue(self.backend.replies(self.room, 0x7c0c, release))
        self.assertEqual(self.backend.replies(self.room, 0x7c0c, release), [])
        self.assertEqual(len(self.room.pending_grenades), 64)
        self.backend.clock = lambda: now + 31
        impact = struct.pack('<I8HBBIBHB', 0, 105, 65520, 160, 105, 65520, 160,
                             0, 0, 1, 0, 1, 0, 0, 255)
        self.assertEqual(self.backend.replies(self.room, 0x7c0c, impact), [])
        self.assertEqual(self.room.pending_grenades, {})
        self.assertTrue(self.backend.replies(self.room, 0x7c0c, release))

    def test_switch_replies_with_owned_entity_slot_and_item(self):
        self.assertEqual(self.request(1), [(0xb334, struct.pack('<HiBIB', 1, 0, 1, 777106, 0))])
        self.assertEqual(self.request(2), [(0xb334, struct.pack('<HiBIB', 1, 0, 2, 777103, 0))])
        self.assertEqual(self.room.active_weapon_index, 2)

    def test_empty_or_invalid_slot_returns_failure_without_changing_active_slot(self):
        self.room.spawned_weapon_ids = (777108, 0, 777103)
        for index in (1, 3, 255):
            self.assertEqual(self.request(index), [(0xb334, struct.pack('<HiBIB', 1, -1, 0, 777108, 0))])
        self.assertEqual(self.room.active_weapon_index, 0)

    def test_foreign_ai_and_nonbattle_requests_are_not_applied(self):
        self.assertEqual(self.request(1, 100), [])
        self.room.round_active = False
        self.assertEqual(self.request(1), [])

    def test_truncated_and_trailing_requests_are_rejected(self):
        body = struct.pack('<IBH', 0, 1, 0)
        for malformed in (body[:-1], body+b'\0'):
            self.assertEqual(self.backend.replies(self.room, 0xea5a, malformed), [])

    def test_local_melee_presentation_uses_configured_action_without_damage(self):
        self.request(1)
        body = struct.pack('<I3HIBH', 0, 238, 1, 0, 880002, 0, 0)
        self.assertEqual(self.backend.replies(self.room, 0x2adc, body),
                         [(0xd725, struct.pack('<HI3HIB', 1, 777106, 238, 1, 500, 880002, 0))])
        self.assertEqual(self.room.active_weapon_index, 1)

    def test_melee_does_not_accept_guns_ai_or_unrecovered_action_ids(self):
        base = struct.pack('<I3HIBH', 0, 238, 1, 0, 0, 0, 0)
        self.assertEqual(self.backend.replies(self.room, 0x2adc, base), [])
        self.request(1)
        for body in (base[:-1], base+b'\0',
                     struct.pack('<I3HIBH', 0, 238, 1, 0, 0, 0, 100),
                     struct.pack('<I3HIBH', 0, 238, 1, 0, 880001, 0, 0),
                     struct.pack('<I3HIBH', 0, 238, 1, 0, 99, 0, 0)):
            self.assertEqual(self.backend.replies(self.room, 0x2adc, body), [])

    def test_observed_zero_melee_request_maps_to_current_saber_presentation(self):
        self.request(1)
        body = struct.pack('<I3HIBH', 0, 241, 13, 0, 0, 0, 0)
        self.assertEqual(self.backend.replies(self.room, 0x2adc, body),
                         [(0xd725, struct.pack('<HI3HIB', 1, 777106, 241, 13, 500, 880002, 0))])

    def test_boost_melee_uses_its_own_configured_presentation(self):
        self.request(1)
        body = struct.pack('<I3HIBH', 0, 241, 13, 0, 880012, 0, 0)
        self.assertEqual(self.backend.replies(self.room, 0x2adc, body),
                         [(0xd725, struct.pack('<HI3HIB', 1, 777106, 241, 13, 366, 880012, 0))])
        foreign = struct.pack('<I3HIBH', 0, 241, 13, 0, 880011, 0, 0)
        self.assertEqual(self.backend.replies(self.room, 0x2adc, foreign), [])
