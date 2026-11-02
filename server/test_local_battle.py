import socket
import struct
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import fake_auth
import local_battle
import xwar_entry


def pilot_record(pilot_id=77, troops=0):
    record = bytearray(157)
    struct.pack_into('<I', record, 0, pilot_id)
    record[4:9] = b'TEST\0'
    record[29:32] = bytes((troops, 1, 0))
    return bytes(record)


class LocalBattleTest(unittest.TestCase):
    def test_stronghold_model_id_resolves_to_existing_model_variant(self):
        from pathlib import Path
        import battlefield_bases
        model = battlefield_bases.MODEL_ID
        group, suffix = divmod(model, 1000000)
        unit, variant = divmod(suffix, 100)
        path = (Path(__file__).resolve().parents[1] / 'GundamOnline_CHINA_已解密/decrypted/chara'
                / f'{group // 100:02}' / f'{group % 100:02}' / f'{unit:04}' / 'model'
                / f'BAM_{group:04}_{unit:04}_{variant:02}.dxg')
        self.assertTrue(path.is_file(), f'missing stronghold model variant: {path}')

    def test_fixed_bases_link_real_stronghold_definitions(self):
        import csv, io, hangar_experiment
        body = local_battle.game_begin_body()
        definitions = {int(row[0]): row for row in csv.reader(io.StringIO(
            hangar_experiment.table_body('msma/msma_settings.csv').decode()))
            if row and not row[0].startswith('#')}
        for index, (team, _) in enumerate(local_battle.deployment_points()):
            kind, owner, troops, name, gauge, chara = struct.unpack_from(
                '<IHH13sII', body, 130 + 42 * index)
            self.assertEqual(kind, 0, 'fixed home bases must use home-base post type')
            self.assertEqual(chara, 0, 'network bases must not also create incomplete local-only actors')
            reservation = self.backend.reserve('a', 77, self.record)
            packet = local_battle.base_entity_replies(reservation)[index][1]
            chara = struct.unpack_from('<I', packet, 13 + 8)[0]
            self.assertIn(chara, definitions)
            self.assertEqual(definitions[chara][7], 'EX_STRONGHOLD')
            self.assertEqual(owner, team)
            models = {r[0] for r in csv.reader(io.StringIO(
                hangar_experiment.table_body('msma/msma_model.csv').decode()))
                if r and not r[0].startswith('#')}
            self.assertIn(definitions[chara][1], models)

    def test_deployment_map_receives_visible_unlocked_post_states(self):
        reservation = self.backend.reserve('a', 77, self.record)
        reservation.started = reservation.connected = True
        replies = self.backend.replies(reservation, 0xE041, b'')
        self.assertIn(0xD1B3, [op for op, _ in replies])
        body = dict(replies)[0xD1B3]
        points = local_battle.deployment_points()
        self.assertEqual(struct.unpack_from('<I', body)[0], len(points))
        self.assertEqual(len(body), 4 + 17 * len(points))
        for i, (team, _) in enumerate(points):
            state = struct.unpack_from('<HHIIBBBBB', body, 4 + 17 * i)
            self.assertEqual(state, (team, team, 10000 if team == 0 else 0,
                                    10000 if team == 1 else 0, 1, 0, 1, 0, 0))
        self.assertLess([op for op, _ in replies].index(0xD1B3),
                        [op for op, _ in replies].index(0x640D))

    def test_prestart_selection_never_acknowledges_actual_spawn_success(self):
        self.backend.units_for_pilot = lambda a, p: [{'uniqid': 123, 'msma_id': 777001,
             'deckslots': [0, 0], 'equipped_weapons': [0, 0, 0]}]
        reservation = self.backend.reserve('a', 77, self.record)
        reservation.started = reservation.connected = True
        self.backend.replies(reservation, 0xE041, b'')
        for body in [bytes.fromhex('00000000ffffffffffffffff0000ffff'),
                     bytes.fromhex('0000000000000000ffffffff0000ffff')]:
            replies = self.backend.replies(reservation, 0xE650, body)
            self.assertNotIn(0x86B2, [op for op, _ in replies])
            self.assertIn(0x640D, [op for op, _ in replies])

    def test_captured_deployment_requests_do_not_treat_post_as_uniqid(self):
        self.backend.units_for_pilot = lambda a, p: [{'uniqid': 123, 'msma_id': 777001,
             'deckslots': [0, 0], 'equipped_weapons': [0, 0, 0]}]
        reservation = self.backend.reserve('a', 77, self.record)
        reservation.started = reservation.connected = True
        self.backend.replies(reservation, 0xE041, b'')
        first = self.backend.replies(reservation, 0xE650, bytes.fromhex('00000000ffffffffffffffff0000ffff'))
        self.assertEqual([op for op, _ in first], [0x717D] * 4 + [0x640D])
        self.assertIsNone(reservation.deployment_at)
        selected = self.backend.replies(reservation, 0xE650, bytes.fromhex('0000000000000000ffffffff0000ffff'))
        self.assertEqual(selected[-1][0], 0x640D)
        self.assertEqual(reservation.selected_post, 0)

    def test_unselected_or_enemy_post_does_not_start_deployment_clock(self):
        self.backend.units_for_pilot = lambda a, p: [{'uniqid': 123, 'msma_id': 777001,
             'deckslots': [0, 0], 'equipped_weapons': [0, 0, 0]}]
        reservation = self.backend.reserve('a', 77, self.record)
        reservation.started = reservation.connected = True
        self.backend.replies(reservation, 0xE041, b'')
        self.now[0] += 30
        self.assertEqual(self.backend.tick(reservation), [])
        enemy = next(i for i, (team, _) in enumerate(local_battle.deployment_points()) if team == 1)
        reply = self.backend.replies(reservation, 0xE650, struct.pack('<IIIBBH', 0, enemy, 0xffffffff, 0, 0, 0xffff))
        self.assertLess(struct.unpack_from('<i', reply[0][1])[0], 0)
        self.assertIsNone(reservation.selected_post)
        self.assertIsNone(reservation.deployment_at)

    def test_game_begin_provides_deployment_points_before_selection(self):
        body = local_battle.game_begin_body()
        self.assertGreater(struct.unpack_from('<I', body, 126)[0], 0)

    def test_first_deployment_waits_for_separate_countdown(self):
        self.backend.units_for_pilot = lambda a, p: [{'uniqid': 123, 'msma_id': 777001,
             'deckslots': [0, 0], 'equipped_weapons': [0, 0, 0]}]
        reservation = self.backend.reserve('a', 77, self.record)
        reservation.started = reservation.connected = True
        replies = self.backend.replies(reservation, 0xE041, b'')
        self.assertEqual(replies[-1][0], 0x640D)
        selected = self.backend.replies(reservation, 0xE650, struct.pack('<IIIBBH', 0, 0, 0xffffffff, 0, 0, 0xffff))
        self.assertEqual([op for op, _ in selected], [0x717D] * 4 + [0x640D])
        self.now[0] += 59
        self.assertEqual(self.backend.tick(reservation), [])
        self.now[0] += 1
        ended = self.backend.tick(reservation)
        self.assertEqual([op for op, _ in ended], [0x7621, 0x86B2, 0x640D, 0x3E23])
        self.assertTrue(reservation.round_active)
        self.assertEqual(ended[-1][1][21], 0)
        self.assertEqual(self.backend.tick(reservation), [])

    def test_countdown_task_flag_is_not_hidden(self):
        import csv, io
        row = list(csv.reader(io.StringIO(xwar_entry.table_body('mission/mission_vs.csv').decode())))[3]
        self.assertEqual(int(row[23]), 0)

    def test_spawn_select_gets_explicit_failure_until_entity_backend_exists(self):
        reservation = self.backend.reserve('a', 77, self.record)
        replies = self.backend.replies(reservation, 0xE650, bytes.fromhex('00000000ffffffffffffffff0000ffff'))
        self.assertEqual([op for op, _ in replies], [0x86B2])
        self.assertLess(struct.unpack_from('<i', replies[0][1])[0], 0)

    def test_spawn_list_request_is_framed_and_uses_owned_units(self):
        self.backend.units_for_pilot = lambda account, pilot: [
            {'uniqid': 123, 'msma_id': 777001, 'deckslots': [0, 0], 'equipped_weapons': [777101, 0, 0]}]
        reservation = self.backend.reserve('a', 77, self.record)
        replies = self.backend.replies(reservation, 0xE041, b'')
        self.assertEqual([op for op, _ in replies], [0x9951, 0x1E2F, 0xAB6F])
        self.assertEqual(struct.unpack_from('<IQI', replies[1][1]), (0, 123, 777001))

    def test_ready_state_does_not_start_battle(self):
        reservation = self.backend.reserve('a', 77, self.record)
        replies = self.backend.replies(reservation, 0x2761, struct.pack('<I', 1))
        self.assertEqual([op for op, _ in replies], [0x339C])
        self.assertFalse(reservation.started)

    def test_cancelled_countdown_does_not_start(self):
        self.backend.countdown_seconds = 1
        reservation = self.backend.reserve('a', 77, self.record)
        self.backend.authenticate(self.identity(reservation.room))
        self.queue.cancel('a', 77, bytes(4))
        self.now[0] += 2
        self.assertEqual(self.backend.tick(reservation), [])

    def test_countdown_initializes_map_only_once_without_ready_click(self):
        self.backend.countdown_seconds = 30
        reservation = self.backend.reserve('a', 77, self.record)
        self.backend.authenticate(self.identity(reservation.room))
        self.assertEqual(self.backend.replies(reservation, 0xF741, b''), [])
        self.now[0] += 29
        self.assertEqual(self.backend.tick(reservation), [])
        self.now[0] += 1
        replies = self.backend.tick(reservation)
        self.assertEqual([op for op, _ in replies], [0x7206, 0x1365])
        self.assertEqual(self.backend.tick(reservation), [])

    def test_preparation_images_and_display_units(self):
        import csv, io
        rows = list(csv.reader(io.StringIO(xwar_entry.table_body('mission/mission_vs.csv').decode())))[2:]
        row = rows[1]
        self.assertEqual(int(row[0]), 30110100)
        self.assertEqual(int(row[1]), 100101)
        self.assertEqual([int(row[i]) for i in (13, 39, 40)], [1, 52, 20])

    def test_explicit_countdown_configuration_is_sent_after_room_initialization(self):
        self.backend.countdown_seconds = 90
        reservation = self.backend.reserve('a', 77, self.record)
        session, replies = self.backend.authenticate(self.identity(reservation.room))
        self.assertEqual(replies[-1], (0x6A8D, struct.pack('<I', 90)))
        self.assertIsNotNone(session)
        with self.assertRaises(ValueError):
            local_battle.countdown_body(-1)

    def setUp(self):
        self.queue = xwar_entry.BookingQueue()
        self.now = [100.0]
        self.backend = local_battle.LocalBattleBackend(self.queue, '127.0.0.1', 30000,
                                                       clock=lambda: self.now[0])
        self.record = pilot_record()
        self.request = struct.pack('<7I', 0, 4, 0, 0, 0, 0, 0)
        self.queue.register('a', 77, self.request, troops=0)

    def identity(self, room, *, user_id=1, world_id=1, pilot_id=77, ticket=None):
        return (struct.pack('<4I', user_id, world_id, pilot_id, room.room_id)
                + (ticket or room.otp).encode() + b'\0\0')

    def test_formal_booking_allocates_room_and_authenticates_real_pilot(self):
        reservation = self.backend.reserve('a', 77, self.record)
        self.assertIs(self.backend.reserve('a', 77, self.record), reservation)
        self.assertEqual(self.queue.info_replies('a', 77, bytes(4))[-1],
                         (0xB099, reservation.room.created_body()))
        self.assertEqual(self.queue.enter('a', 77, struct.pack('<II', 0, reservation.room.room_id)),
                         reservation.room.enter_body())
        session, replies = self.backend.authenticate(self.identity(reservation.room))
        self.assertIs(session, reservation)
        self.assertEqual([opcode for opcode, _ in replies], [0xA5DA, 0xBDD6, 0x5913])
        self.assertEqual(replies[1][1][6:163], self.record)
        ready = self.backend.replies(session, 0x2761, struct.pack('<I', 1))
        self.assertEqual(ready[0], (0x339C, struct.pack('<4I', 0, 1, 77, 1)))
        self.assertEqual(len(ready), 1)
        self.assertEqual(self.backend.replies(session, 0xD97D, b''), [(0x14C5, b'')])
        self.assertFalse(self.backend.valid(session))

    def test_tickets_enforce_identity_expiry_cancellation_and_no_replay(self):
        reservation = self.backend.reserve('a', 77, self.record)
        for changes in [dict(user_id=2), dict(world_id=2), dict(pilot_id=78), dict(ticket='wrong')]:
            session, replies = self.backend.authenticate(self.identity(reservation.room, **changes))
            self.assertIsNone(session)
            self.assertEqual(struct.unpack_from('<i', replies[0][1])[0], -1)
        session, _ = self.backend.authenticate(self.identity(reservation.room))
        self.assertIsNotNone(session)
        self.assertIsNone(self.backend.authenticate(self.identity(reservation.room))[0])
        self.backend.disconnect(session)
        self.assertIsNone(self.backend.authenticate(self.identity(reservation.room))[0])
        self.queue.register('a', 77, self.request)
        expired = self.backend.reserve('a', 77, self.record)
        self.now[0] += 301
        self.assertIsNone(self.backend.authenticate(self.identity(expired.room))[0])
        renewed = self.backend.reserve('a', 77, self.record)
        self.assertNotEqual(renewed.room.otp, expired.room.otp)
        self.queue.cancel('a', 77, bytes(4))
        self.assertIsNone(self.backend.authenticate(self.identity(renewed.room))[0])

    def test_invalid_records_and_request_shapes_do_not_get_room_or_ready(self):
        self.assertIsNone(self.backend.reserve('a', 77, bytes(156)))
        self.assertIsNone(self.backend.reserve('a', 77, pilot_record(78)))
        self.assertIsNone(self.backend.reserve('a', 77, pilot_record(77, 3)))
        reservation = self.backend.reserve('a', 77, self.record)
        for body in (b'', bytes(17), self.identity(reservation.room) + b'extra'):
            self.assertIsNone(local_battle.auth_identity(body))
        self.assertEqual(self.backend.replies(reservation, 0x2761, struct.pack('<I', 999)), [])
        self.assertEqual(self.backend.replies(reservation, 0xF741, b'invalid'), [])

    def test_native_room_entry_stat_two_is_acknowledged(self):
        reservation = self.backend.reserve('a', 77, self.record)
        self.assertEqual(self.backend.replies(reservation, 0x2761, struct.pack('<I', 2)),
                         [(0x339C, struct.pack('<4I', 0, 1, 77, 2))])


class BattleTransportIntegrationTest(unittest.TestCase):
    def test_loopback_formal_handoff_encrypted_battle_auth_ready_and_exit(self):
        queue = xwar_entry.BookingQueue()
        record = pilot_record()
        keymat = bytes.fromhex('11' * 16 + '22' * 16)
        args = SimpleNamespace(login_seq=True, idle=3, sweep=True)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            backend = local_battle.LocalBattleBackend(queue, '127.0.0.1', listener.getsockname()[1])
            with patch.object(fake_auth, 'HANGAR_EXPERIMENT', True), \
                 patch.object(fake_auth, 'LOCAL_BATTLE', backend), \
                 patch.object(xwar_entry, 'BOOKINGS', queue), \
                 patch.object(fake_auth, 'KEYHEX', [keymat.hex()]), \
                 patch.object(fake_auth, 'log'), \
                 patch.object(fake_auth, 'saved_pilot_records', return_value={0: record, 1: None}):
                fake_auth.hall_replies(0x2EFF, struct.pack('<7I', 0, 4, 0, 0, 0, 0, 0), 'a', 77)
                notice = dict(fake_auth.hall_replies(0xFC4B, bytes(4), 'a', 77))[0xB099]
                matching, room_id, wait, mission = struct.unpack('<4I', notice)
                handoff = fake_auth.hall_replies(0x846A, struct.pack('<II', matching, room_id), 'a', 77)
                self.assertEqual(handoff[0][0], 0x5383)
                reservation = backend.reservations[('a', 77)]

                def serve():
                    connection, address = listener.accept()
                    fake_auth.handle(connection, address, args, 1, 'keyhex')

                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
                n_up = n_down = 0
                with socket.create_connection(listener.getsockname(), timeout=3) as client:
                    def exact(size):
                        result = b''
                        while len(result) < size:
                            part = client.recv(size - len(result))
                            if not part:
                                raise AssertionError('server closed before complete reply')
                            result += part
                        return result

                    def send(opcode, body):
                        nonlocal n_up
                        plain = bytes.fromhex(fake_auth.op_block(opcode, body))
                        cipher = b''.join(fake_auth.camellia_block(keymat[16:], plain[i:i + 16], n_up + i // 16)
                                          for i in range(0, len(plain), 16))
                        n_up += len(plain) // 16
                        client.sendall(struct.pack('<I', len(plain)) + cipher)

                    def receive():
                        nonlocal n_down
                        size = struct.unpack('<I', exact(4))[0]
                        plain, n_down = fake_auth.decrypt_uplink(keymat[16:] + keymat[:16], exact(size), n_down)
                        return [(op, body) for op, body in fake_auth.iter_type0(plain) if op != 0xFFFF]

                    client.sendall(bytes(16))
                    self.assertEqual(exact(32), keymat)
                    send(0x34A9, bytes(12))
                    self.assertEqual(receive()[0][0], 0xDE24)
                    send(0xF24B, struct.pack('<4I', 1, 1, 77, room_id) + reservation.room.otp.encode() + b'\0\0')
                    self.assertEqual(receive(), [(0xA5DA, local_battle.authenticate_body(room_id))])
                    self.assertEqual(receive(), [(0xBDD6, local_battle.member_body(record, 1))])
                    self.assertEqual(receive(), [(0x5913, struct.pack('<II', 1, 77))])
                    send(0x2761, struct.pack('<I', 1))
                    self.assertEqual(receive(), [(0x339C, struct.pack('<4I', 0, 1, 77, 1))])
                    send(0xD97D, b'')
                    self.assertEqual(receive(), [(0x14C5, b'')])
                worker.join(timeout=3)
                self.assertFalse(worker.is_alive(), 'battle worker did not close')
                self.assertFalse(queue.rooms)


if __name__ == '__main__':
    unittest.main()
