import struct
import unittest
import local_battle
import xwar_entry


class DeploymentSelectionTest(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        queue = xwar_entry.BookingQueue()
        queue.register('test', 77, struct.pack('<7I', 0, 4, 0, 0, 0, 0, 0))
        self.backend = local_battle.LocalBattleBackend(queue, '127.0.0.1', 30000, clock=lambda: self.now)
        self.backend.units_for_pilot = lambda a, p: [{'uniqid': 123, 'msma_id': 777001,
                                                    'deckslots': [0, 0]}]
        self.room = self.backend.reserve('test', 77, struct.pack('<I', 77) + bytes(153))
        self.room.started = self.room.connected = True
        self.backend.replies(self.room, 0xE041, b'')

    def test_selected_post_is_a_spawn_kind_not_a_mech_index(self):
        reply = dict(self.backend.replies(self.room, 0xE650,
                     struct.pack('<IIIBBH', 0, 0, 0xffffffff, 0, 0, 0xffff)))
        # 4407E0 counts mstype=1 as post selection. Mech index zero means no selection.
        self.assertEqual(reply[0x640D][8], 1)

    def test_base_entities_wait_for_loaded_client_selection_and_are_sent_once(self):
        self.assertFalse(self.room.bases_sent,
                         'E041 is sent during scene loading, before world/UI are ready')
        request = struct.pack('<IIIBBH', 0, 0xffffffff, 0xffffffff, 0, 0, 0xffff)
        first = self.backend.replies(self.room, 0xE650, request)
        self.assertEqual([op for op, _ in first], [0x717D] * 4 + [0x640D])
        self.assertTrue(self.room.bases_sent)
        self.assertEqual([op for op, _ in self.backend.replies(self.room, 0xE650, request)], [0x640D])

    def test_fixed_base_selection_uses_respawn_entity_and_kind_two(self):
        # Fixed-base sender uses post=FFFFFFFF and respawn_ent_id, distinct from a post.
        reply = dict(self.backend.replies(self.room, 0xE650,
                     struct.pack('<IIIBBH', 0, 0xffffffff, 0xffffffff, 0, 0, 100)))
        self.assertEqual(self.room.selected_post, 0)
        self.assertEqual(reply[0x640D][8], 2)
        self.assertEqual(struct.unpack_from('<H', reply[0x640D], 25)[0], 100)

    def test_enemy_or_unknown_base_entity_does_not_change_selection(self):
        for entity in (102, 999):
            reply = dict(self.backend.replies(self.room, 0xE650,
                         struct.pack('<IIIBBH', 0, 0xffffffff, 0xffffffff, 0, 0, entity)))
            self.assertIn(0x86B2, reply)
            self.assertIsNone(self.room.selected_post)

    def test_initial_game_resume_handshake_has_an_explicit_resume_reply(self):
        self.room.round_active = True
        self.assertEqual(self.backend.replies(self.room, 0xCB97, struct.pack('<IB', 1, 0) + b'\0'),
                         [(0x8297, b'')])

    def test_base_entities_do_not_claim_the_human_pilot_identity(self):
        for _, body in local_battle.base_entity_replies(self.room):
            self.assertEqual(struct.unpack_from('<II', body, 5), (0, 0),
                             'base owner must not reuse the player world/pilot identity')


if __name__ == '__main__':
    unittest.main()
