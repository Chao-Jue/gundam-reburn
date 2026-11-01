"""Regression for the empty sorted list behind the 2026-10-29 crash.

Runs the current client's 0x604830 comparator lookup offline, not a live game.
"""
import struct
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EAX

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import fake_auth


def native_sort_lookup(sort_type, order):
    image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(0x400000, (len(image) + 4095) & ~4095)
    uc.mem_write(0x400000, image)
    uc.mem_map(0x20000000, 0x10000)
    uc.mem_write(0x20008000, struct.pack('<III', 0x20009000, sort_type, order))
    uc.reg_write(UC_X86_REG_ESP, 0x20008000)
    uc.emu_start(0x604830, 0x20009000, count=10000)
    return uc.reg_read(UC_X86_REG_EAX)


class NativeSortTest(unittest.TestCase):
    def test_invalid_zero_has_no_native_comparator(self):
        self.assertEqual(native_sort_lookup(0, 0), 0)
        self.assertNotEqual(native_sort_lookup(1, 0), 0)

    def test_initialization_sort_is_accepted_by_native_client(self):
        for units in ([], [fake_auth.hangar_experiment.gm_unit()]):
            with patch.object(fake_auth, 'HANGAR_EXPERIMENT', False), \
                 patch.object(fake_auth.HANGAR_STORE, 'units', return_value=units):
                begin = fake_auth.hall_replies(0x16AC, b'', 'regression')[0][1]
            sort_type, order = struct.unpack_from('<II', begin, 20)
            self.assertNotEqual(native_sort_lookup(sort_type, order), 0,
                                'invalid sort leaves +0x9D4 sorted vector empty before 0x787BB6')


if __name__ == '__main__':
    unittest.main()
