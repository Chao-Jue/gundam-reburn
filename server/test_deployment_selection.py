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

    def test_mech_selection_preview_keeps_selection_open_before_deployment_timer(self):
        replies = dict(self.backend.replies(self.room, 0xE650,
                       struct.pack('<IIIBBH', 0, 0xffffffff, 0xffffffff, 0, 0, 0xffff)))
        self.assertIn(0x86B2, replies,
                      'AF46B0/A53100 must clear selection busy and set game+109F8 before spawn')
        self.assertEqual(struct.unpack_from('<iI', replies[0x86B2]), (1, 0))
        self.assertFalse(self.room.entities_ready)
        self.assertIsNone(self.room.deployment_at)

    def test_default_home_post_counts_for_the_visible_base(self):
        replies = dict(self.backend.replies(self.room, 0xE650,
                       struct.pack('<IIIBBH', 0, 0, 0xffffffff, 0, 0, 0xffff)))
        self.assertIn(0x86B2, replies)
        # Live client member entry was kind1/entityFFFF/post0; the base widget
        # compares entity100 and therefore counted zero. Home posts are aliases.
        self.assertEqual(replies[0x640D], local_battle.prestart_body(60, 0, 0, 100))

    def test_selected_post_is_a_spawn_kind_not_a_mech_index(self):
        reply = dict(self.backend.replies(self.room, 0xE650,
                     struct.pack('<IIIBBH', 0, 0, 0xffffffff, 0, 0, 0xffff)))
        # Home post aliases also identify their visible fixed base, kind2.
        # Mech index zero must never be encoded as no selection.
        self.assertEqual(reply[0x640D][8], 2)

    def test_base_entities_wait_for_loaded_client_selection_and_are_sent_once(self):
        self.assertFalse(self.room.bases_sent,
                         'E041 is sent during scene loading, before world/UI are ready')
        request = struct.pack('<IIIBBH', 0, 0xffffffff, 0xffffffff, 0, 0, 0xffff)
        first = self.backend.replies(self.room, 0xE650, request)
        self.assertEqual([op for op, _ in first], [0x717D] * 4 + [0x86B2, 0x640D])
        self.assertTrue(self.room.bases_sent)
        self.assertEqual([op for op, _ in self.backend.replies(self.room, 0xE650, request)], [0x86B2, 0x640D])

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

    def test_final_selection_ack_precedes_self_creation(self):
        self.select_base(100)
        self.now = self.room.deployment_at
        self.backend.tick(self.room)
        self.now += .5
        packets = self.backend.tick(self.room)
        opcodes = [op for op, _ in packets]
        self.assertLess(opcodes.index(0x86B2),opcodes.index(0x7621),
                        'finish the selection transaction before creating its owned actor')
        self.assertEqual(struct.unpack_from('<i',dict(packets)[0x86B2])[0],0)

    def test_timer_spawns_without_an_unobserved_second_client_submission(self):
        self.select_base(100)
        self.now = self.room.deployment_at
        self.assertEqual(self.backend.tick(self.room),
                         [(0x640D,local_battle.selected_prestart_body(self.room,0))])
        self.assertFalse(self.room.entities_ready)
        self.assertEqual(self.backend.tick(self.room),[])
        self.assertEqual(self.backend.replies(self.room,0xE650,
            struct.pack('<IIIBBH',0,0xffffffff,0xffffffff,0,0,0xffff)),[])
        self.assertNotIn(0x86B2,self.select_base(100))
        self.now += .5
        packets = self.backend.tick(self.room)
        self.assertIn(0x7621,[op for op,_ in packets],
                      'native client does not automatically submit E650 again at zero')
        self.assertTrue(self.room.round_active)

    def test_base_entities_do_not_claim_the_human_pilot_identity(self):
        for _, body in local_battle.base_entity_replies(self.room):
            self.assertEqual(struct.unpack_from('<II', body, 5), (0, 0),
                             'base owner must not reuse the player world/pilot identity')

    def select_base(self, entity):
        return dict(self.backend.replies(self.room, 0xE650,
                    struct.pack('<IIIBBH', 0, 0xffffffff, 0xffffffff, 0, 0, entity)))

    def test_warp_selection_moves_waiting_member_from_a_to_b_and_spawns_at_b(self):
        self.select_base(100)
        deadline = self.room.deployment_at
        reply = dict(self.backend.replies(self.room, 0x800A,
                     struct.pack('<IIBH', 0xffffffff, 0xffffffff, 0, 101)))
        self.assertEqual(self.room.selected_post, 1)
        self.assertEqual(self.room.deployment_at, deadline)
        # 8852F0 compares entry+2 against the base entity to count waiting pilots.
        self.assertEqual(reply[0x640D], local_battle.prestart_body(60, 0, 0xffff, 101))
        self.now = deadline
        self.backend.tick(self.room)
        self.now += .5
        own = dict(self.backend.tick(self.room))[0x7621]
        expected = local_battle.battle_entities.appear_self_body(
            local_battle.spawn_unit_body(self.backend.units_for_pilot('', 0)[0], 0),
            1, (30000, 500, -12500), team=0, troops=0, hp=3425, shield_hp=0)
        self.assertEqual(own, expected)

    def test_refresh_preserves_base_waiting_count(self):
        selected = self.select_base(101)[0x640D]
        self.assertEqual(dict(self.backend.replies(self.room, 0xE041, b''))[0x640D], selected)

    def test_invalid_warp_does_not_change_selection(self):
        self.select_base(101)
        for body in (b'', bytes(12), struct.pack('<IIBH', 0xffffffff, 0xffffffff, 0, 102),
                     struct.pack('<IIBH', 0xffffffff, 0xffffffff, 1, 100),
                     struct.pack('<IIBH', 0xffffffff, 0, 0, 100)):
            self.backend.replies(self.room, 0x800A, body)
            self.assertEqual((self.room.selected_post, self.room.selected_entity), (1, 101))

    def test_base_and_deployment_coordinates_are_independent(self):
        bases = local_battle.base_entity_replies(self.room)
        expected_positions = ((21000, -448, 12500), (27000, 24, -12500),
                              (-27000, 26, 11000), (-21500, -478, -14000))
        for i, ((_, packet), position) in enumerate(zip(bases, expected_positions)):
            team = 0 if i < 2 else 1
            unit = {'uniqid': 900000000 + i, 'msma_id': local_battle.battlefield_bases.MSMA_ID}
            expected = local_battle.battle_entities.appear_body(
                local_battle.spawn_unit_body(unit, 255), 100 + i, position, team=team,
                troops=team, world_id=0, pilot_id=0, letter=i % 2)
            self.assertEqual(packet, expected)
            self.assertNotEqual(local_battle.deployment_points()[i][1], position)


if __name__ == '__main__':
    unittest.main()
