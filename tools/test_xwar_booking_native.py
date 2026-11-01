"""Execute the current client's field readers, excluding transport and UI callbacks."""
from pathlib import Path
import struct
import sys
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import xwar_entry


class BookingNativeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()

    def parse(self, body, start, pointer_offset, success, failures):
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000, (len(self.image) + 4095) & ~4095)
        u.mem_write(0x400000, self.image)
        u.mem_map(0x20000000, 0x10000)
        sp, source, target = 0x20008000, 0x20001000, 0x20002000
        u.reg_write(UC_X86_REG_ESP, sp)
        u.mem_write(source, body)
        u.mem_write(sp + pointer_offset, struct.pack('<I', target))
        u.mem_write(sp + 0x14, struct.pack('<II', source, source + len(body)))
        reached = []

        def stop(machine, address, size, data):
            if address == success or address in failures:
                reached.append(address)
                machine.emu_stop()

        u.hook_add(UC_HOOK_CODE, stop)
        u.emu_start(start, 0xAD5E25, count=2000)
        self.assertEqual(len(reached), 1, 'parser did not reach a terminal branch')
        consumed = struct.unpack('<I', u.mem_read(sp + 0x14, 4))[0] - source
        return reached[0] == success, consumed, bytes(u.mem_read(target, len(body)))

    def booking(self, body):
        return self.parse(body, 0xACA351, 0x30, 0xACA4FA, {0xACA380, 0xACA4E0})

    def cancellation(self, body):
        return self.parse(body, 0xAB6A94, 0x24, 0xAB6B29, {0xAB6AC3, 0xAB6B0F})

    def test_current_booking_reply_is_consumed_exactly(self):
        body = xwar_entry.BookingQueue().register('a', 1, struct.pack('<7I', 0, 4, 0, 0, 0, 0, 0))
        self.assertEqual(self.booking(body), (True, 25, body))

    def test_reference_21_byte_booking_reply_is_rejected(self):
        self.assertFalse(self.booking(bytes(21))[0])

    def test_current_cancel_reply_is_consumed_exactly(self):
        body = xwar_entry.BookingQueue().cancel('a', 1, bytes(4))
        self.assertEqual(self.cancellation(body), (True, 8, body))

    def test_reference_12_byte_cancel_reply_is_rejected(self):
        self.assertEqual(self.cancellation(bytes(12))[:2], (False, 8))

    def test_status_info_uses_native_seven_u32_fields(self):
        queue = xwar_entry.BookingQueue()
        queue.set_status(0, active=True, remaining_count=1, remaining_seconds=90)
        body = queue.info_replies('a', 1, bytes(4))[0][1]
        self.assertEqual(self.parse(body, 0xAD18B8, 0x28, 0xAD1A11,
                                   {0xAD18E7, 0xAD19F7}), (True, 28, body))

    def test_room_created_uses_native_four_u32_fields(self):
        room = xwar_entry.BattleRoom(0, 1234, 10001, '127.0.0.1', 30100, 'test-ticket', 10)
        body = room.created_body()
        self.assertEqual(self.parse(body, 0xAC1BA0, 0x34, 0xAC1C81,
                                   {0xAC1BCF, 0xAC1C67}), (True, 16, body))

    def test_native_room_entry_accepts_compact_strings_and_error_reply(self):
        room = xwar_entry.BattleRoom(0, 1234, 10001, '127.0.0.1', 30100, 'test-ticket')
        error = xwar_entry.BookingQueue().enter('a', 1, struct.pack('<II', 0, 1234))
        for body in (room.enter_body(), error):
            accepted, consumed, _ = self.parse(body, 0xAB15F7, 0x30, 0xAB1736,
                                               {0xAB1626, 0xAB1690, 0xAB171C})
            self.assertTrue(accepted)
            self.assertEqual(consumed, len(body))


if __name__ == '__main__':
    unittest.main()
