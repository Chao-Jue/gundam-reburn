"""Current battle decoder execution, excluding UI callbacks and resource loading."""
from pathlib import Path
import struct
import sys
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EAX, UC_X86_REG_EIP

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import local_battle


class BattleRoomNativeTest(unittest.TestCase):
    def test_linked_base_definition_maps_to_native_stronghold_category(self):
        import csv, io, hangar_experiment, battlefield_bases
        rows = csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_settings.csv').decode()))
        row = next(r for r in rows if r and r[0] == str(battlefield_bases.MSMA_ID))
        token = row[7].encode('ascii')
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000, (len(self.image) + 4095) & ~4095)
        u.mem_write(0x400000, self.image)
        u.mem_map(0x20000000, 0x10000)
        obj, sp, stop = 0x20001000, 0x20008000, 0x20009000
        u.mem_write(obj + 4, token + b'\0')
        u.mem_write(obj + 0x14, struct.pack('<II', len(token), 15))
        u.mem_write(sp, struct.pack('<II', stop, obj))
        u.reg_write(UC_X86_REG_ESP, sp)

        def compare(machine, address, size, data):
            if address != 0x40CEF0:
                return
            stack = machine.reg_read(UC_X86_REG_ESP)
            ret, pos, length, right, right_length = struct.unpack('<5I', machine.mem_read(stack, 20))
            this = machine.reg_read(UC_X86_REG_ECX)
            left = bytes(machine.mem_read(this + 4 + pos, length))
            other = bytes(machine.mem_read(right, right_length))
            machine.reg_write(UC_X86_REG_EAX, 0 if left == other else 1)
            machine.reg_write(UC_X86_REG_ESP, stack + 20)
            machine.reg_write(UC_X86_REG_EIP, ret)

        u.hook_add(UC_HOOK_CODE, compare)
        u.emu_start(0x54D210, stop, count=10000)
        self.assertEqual(u.reg_read(UC_X86_REG_EAX), 6)  # EX_STRONGHOLD, distinct from EX_RESPAWNPOST=7

    def test_home_base_posts_pass_native_spawn_predicate(self):
        # The previous 885C60 rule-0x15 fixture was not the live rule (0x14).
        # Verify actual home-base eligibility; do not equate a rule predicate with UI rendering.
        body = local_battle.game_begin_body()
        states = local_battle.deployment_post_states_body()
        for index, (team, _) in enumerate(local_battle.deployment_points()):
            post_type = struct.unpack_from('<I', body, 130 + index * 42)[0]
            visible, locked, keep = struct.unpack_from('<3B', states, 4 + index * 17 + 12)
            u = Uc(UC_ARCH_X86, UC_MODE_32)
            u.mem_map(0x400000, (len(self.image) + 4095) & ~4095)
            u.mem_write(0x400000, self.image)
            u.mem_map(0x20000000, 0x10000)
            obj, sp, stop = 0x20001000, 0x20008000, 0x20009000
            # 42D350: nonnegative label index, visible, matching team, type2 keep.
            u.mem_write(obj, struct.pack('<I', post_type))
            u.mem_write(obj + 8, struct.pack('<I', team))
            u.mem_write(obj + 0x44, struct.pack('<I', index))
            u.mem_write(obj + 0x54, bytes([visible]))
            u.mem_write(obj + 0x58, bytes([locked, keep]))
            u.mem_write(sp, struct.pack('<II', stop, team))
            u.reg_write(UC_X86_REG_ESP, sp)
            u.reg_write(UC_X86_REG_ECX, obj)
            u.emu_start(0x42D350, stop, count=100)
            self.assertEqual(u.reg_read(UC_X86_REG_EAX) & 255, 1,
                             f'post {index}: native spawn predicate rejects point')

    def test_deployment_post_states_native_decoder(self):
        body = local_battle.deployment_post_states_body()
        accepted, consumed, _ = self.parse(body, 0xA80EFB, 0x28, 0xA80FB4,
                                           {0xA80F1C, 0xA80F84, 0xA80F9D})
        self.assertTrue(accepted)
        self.assertEqual(consumed, len(body))
        for invalid in (body[:-1], body + b'\0', struct.pack('<I', 51)):
            self.assertFalse(self.parse(invalid, 0xA80EFB, 0x28, 0xA80FB4,
                                        {0xA80F1C, 0xA80F84, 0xA80F9D})[0])

    def test_prestart_and_progress_messages(self):
        for body, start, ptr, success, failures in [
                (local_battle.prestart_body(15), 0xA720E6, 0x10, 0xA7234C, {0xA72115, 0xA72144, 0xA72335}),
                (local_battle.prestart_body(60, 0, 0), 0xA720E6, 0x10, 0xA7234C, {0xA72115, 0xA72144, 0xA72335}),
                (local_battle.mission_progress_body(False), 0xA6B847, 0x28, 0xA6B899, {0xA6B878})]:
            accepted, consumed, _ = self.parse(body, start, ptr, success, failures)
            self.assertTrue(accepted)
            self.assertEqual(consumed, len(body))
    def test_spawn_select_failure_has_all_six_fields(self):
        body = struct.pack('<iIIIH', -1, 0, 0, 0xffff, 0xffff) + b'\0'
        accepted, consumed, _ = self.parse(body, 0xA774E0, 0x44, 0xA775FB,
                                           {0xA7750F, 0xA775DA})
        self.assertTrue(accepted)
        self.assertEqual(consumed, len(body))

    def test_current_mission_countdown_predicate_accepts_corrected_task(self):
        import csv, io, xwar_entry
        row = list(csv.reader(io.StringIO(xwar_entry.table_body('mission/mission_vs.csv').decode())))[3]
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000, (len(self.image) + 4095) & ~4095)
        u.mem_write(0x400000, self.image)
        u.mem_map(0x20000000, 0x10000)
        function = struct.unpack_from('<I', self.image, 0xCBE658 + 12 - 0x400000)[0]
        for flag, expected in [(1, 0), (int(row[23]), 1)]:
            u.mem_write(0x20001050, bytes([flag]))
            u.mem_write(0x20008000, struct.pack('<I', 0x20009000))
            u.reg_write(UC_X86_REG_ESP, 0x20008000)
            u.reg_write(UC_X86_REG_ECX, 0x20001000)
            u.emu_start(function, 0x20009000, count=20)
            self.assertEqual(u.reg_read(UC_X86_REG_EAX) & 255, expected)
    def test_spawn_list_one_consumes_owned_unit_identity(self):
        body = struct.pack('<I', 0) + local_battle.spawn_unit_body(
            {'uniqid': 123, 'msma_id': 777001, 'equipped_weapons': [777101, 0, 0]}, 0)
        accepted, consumed, output = self.parse(body, 0xA689BF, 0x28, 0xA68A4E,
                                               {0xA689EE, 0xA68A37})
        self.assertTrue(accepted)
        self.assertEqual(consumed, len(body))
        self.assertEqual(struct.unpack_from('<QI', output, 4), (123, 777001))

    def test_spawn_list_begin_and_end_are_exact(self):
        accepted, consumed, _ = self.parse(struct.pack('<II', 0, 1), 0xA79EC9, 0x10,
                                          0xA79F58, {0xA79EF8, 0xA79F41})
        self.assertTrue(accepted)
        self.assertEqual(consumed, 8)
        accepted, consumed, _ = self.parse(b'', 0xA7D372, None, 0xA7D3A1, {0xA7D37E})
        self.assertTrue(accepted)
        self.assertEqual(consumed, 0)
    def test_game_begin_scene_header_and_empty_deployment_arrays(self):
        body = local_battle.game_begin_body()
        accepted, consumed, _ = self.parse(body, 0xA6684E, 0x20, 0xA66CA6,
                                           {0xA66883, 0xA66AE0, 0xA66C8F})
        self.assertTrue(accepted)
        self.assertEqual(consumed, len(body))

    def test_game_start_reply_has_five_u32(self):
        body = struct.pack('<5I', 0, 0, 1200, 0, 0)
        accepted, consumed, _ = self.parse(body, 0xA74BFD, 0x10, 0xA74D00,
                                           {0xA74C2C, 0xA74CE9})
        self.assertTrue(accepted)
        self.assertEqual(consumed, 20)
    @classmethod
    def setUpClass(cls):
        cls.image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()

    def parse(self, body, start, pointer_offset, success, failures):
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000, (len(self.image) + 4095) & ~4095)
        u.mem_write(0x400000, self.image)
        u.mem_map(0x20000000, 0x10000)
        sp, source, target = 0x20008000, 0x20001000, 0x20003000
        u.reg_write(UC_X86_REG_ESP, sp)
        if body:
            u.mem_write(source, body)
        if pointer_offset is not None:
            u.mem_write(sp + pointer_offset, struct.pack('<I', target))
        u.mem_write(sp + 0x14, struct.pack('<II', source, source + len(body)))
        reached = []

        def stop(machine, address, size, data):
            if address == success or address in failures:
                reached.append(address)
                machine.emu_stop()

        u.hook_add(UC_HOOK_CODE, stop)
        u.emu_start(start, 0xA85797, count=20000)
        self.assertEqual(len(reached), 1, 'battle parser did not reach a terminal branch')
        consumed = struct.unpack('<I', u.mem_read(sp + 0x14, 4))[0] - source
        return reached[0] == success, consumed, bytes(u.mem_read(target, 1024))

    def auth(self, body):
        return self.parse(body, 0xA7A8B1, 0x20, 0xA7ABFF, {0xA7A8E6, 0xA7A94B, 0xA7ABE8})

    def test_battle_auth_has_current_19_fields_and_map_is_at_correct_offset(self):
        body = local_battle.authenticate_body(1234)
        accepted, consumed, output = self.auth(body)
        self.assertTrue(accepted)
        self.assertEqual(consumed, len(body))
        self.assertEqual(len(body), 632 + len(local_battle.ROOM_NAME))
        self.assertEqual(struct.unpack_from('<I', output, 93)[0], local_battle.MAP_ID)

    def test_reference_auth_extra_ranker_field_is_rejected(self):
        body = local_battle.authenticate_body(1234)
        offset = 8 + len(local_battle.ROOM_NAME) + 1 + 12
        self.assertFalse(self.auth(body[:offset] + bytes(4) + body[offset:])[0])

    def test_member_add_reuses_157_byte_saved_pilot(self):
        record = struct.pack('<I', 77) + b'TEST\0' + bytes(148)
        body = local_battle.member_body(record, 1)
        accepted, consumed, output = self.parse(body, 0xA7F925, 0x20, 0xA7FB18,
                                                {0xA7F954, 0xA7FB01})
        self.assertTrue(accepted)
        self.assertEqual(consumed, 179)
        self.assertEqual(struct.unpack_from('<I', output, 6)[0], 77)

    def test_ready_reply_is_four_u32(self):
        body = struct.pack('<4I', 0, 1, 77, 1)
        accepted, consumed, _ = self.parse(body, 0xA6A3B2, 0x10, 0xA6A48D,
                                          {0xA6A3E1, 0xA6A476})
        self.assertTrue(accepted)
        self.assertEqual(consumed, 16)

    def test_exit_has_no_result_field(self):
        import xwar_entry
        queue = xwar_entry.BookingQueue()
        backend = local_battle.LocalBattleBackend(queue, '127.0.0.1', 30000)
        record = struct.pack('<I', 77) + bytes(153)
        queue.register('a', 77, struct.pack('<7I', 0, 4, 0, 0, 0, 0, 0))
        reservation = backend.reserve('a', 77, record)
        body = backend.replies(reservation, 0xD97D, b'')[0][1]
        accepted, consumed, _ = self.parse(body, 0xA66712, None, 0xA66741, {0xA6671E})
        self.assertTrue(accepted)
        self.assertEqual(consumed, 0)

    def test_countdown_is_exactly_one_u32(self):
        body = local_battle.countdown_body(90)
        accepted, consumed, _ = self.parse(body, 0xA73151, 0x34, 0xA731A3, {0xA73182})
        self.assertTrue(accepted)
        self.assertEqual(consumed, 4)


if __name__ == '__main__':
    unittest.main()
