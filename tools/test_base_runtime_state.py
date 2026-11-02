"""Execute the native base eligibility gate with explicit actor state."""
from pathlib import Path
import struct
import unittest
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_ESP


class BaseRuntimeStateTest(unittest.TestCase):
    def test_native_base_eligibility_requires_own_team_and_permission_bit(self):
        image = (Path(__file__).resolve().parents[1] / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000, (len(image) + 4095) & ~4095)
        u.mem_write(0x400000, image)
        u.mem_map(0x20000000, 0x10000)
        marker, ref, actor, component, game, stack, stop = [0x20000000 + n * 0x1000 for n in range(7)]
        u.mem_write(0x1161f28, struct.pack('<I', game - 0x3a9cc))
        u.mem_write(game, struct.pack('<I', 0))  # actual 42E880 own-team lookup
        u.mem_write(marker + 0x114, struct.pack('<I', ref))
        u.mem_write(ref, struct.pack('<I', actor))
        u.mem_write(actor + 0x35c, struct.pack('<I', component))
        for team, flags, expected in [(0, 0, 0), (0, 1, 1), (1, 1, 0), (0, 128, 0)]:
            with self.subTest(team=team, flags=flags):
                u.mem_write(actor + 0xf4, struct.pack('<II', team, 0xffffffff))
                u.mem_write(component + 0xd2, bytes([flags]))
                u.mem_write(stack, struct.pack('<I', stop))
                u.reg_write(UC_X86_REG_ESP, stack)
                u.reg_write(UC_X86_REG_ECX, marker)
                u.emu_start(0x877760, stop, count=100)
                self.assertEqual(u.reg_read(UC_X86_REG_EAX) & 255, expected)


if __name__ == '__main__':
    unittest.main()
