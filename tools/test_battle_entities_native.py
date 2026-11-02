"""Validate complete entity packets with the current native dispatcher readers."""
import struct
import sys
import unittest
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EAX

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import battle_entities
import local_battle


class EntityWireNativeTest(unittest.TestCase):
    def test_unowned_base_identity_resolves_a_vacant_native_member_slot(self):
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000, (len(image) + 4095) & ~4095)
        u.mem_write(0x400000, image)
        u.mem_map(0x20000000, 0x100000)
        game, stack, stop = 0x20000000, 0x20080000, 0x20090000
        u.mem_write(0x1161f28, struct.pack('<I', game))
        u.mem_write(game + 0x46c, struct.pack('<I', 77))
        # First member is the human; the next record is a vacant world=0 slot.
        u.mem_write(game + 0x11098 + 0x24, struct.pack('<II', 1, 77))
        u.mem_write(stack, struct.pack('<III', stop, 0, 0))
        u.reg_write(UC_X86_REG_ESP, stack)
        u.reg_write(UC_X86_REG_ECX, game)
        u.emu_start(0x44e120, stop, count=1000)
        self.assertEqual(u.reg_read(UC_X86_REG_EAX), game + 0x11098 + 0x188)

    def parse(self, body, own, *, capture=False):
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x400000, (len(image) + 4095) & ~4095)
        u.mem_write(0x400000, image)
        u.mem_map(0x20000000, 0x100000)
        sp, source, arena = 0x20008000, 0x20001000, 0x20040000
        u.mem_write(source, body)
        u.mem_write(sp + 0x14, struct.pack('<II', source, source + len(body)))
        u.mem_write(sp + 0x20, struct.pack('<I', arena + 1))
        u.mem_write(sp + (0x4c if own else 0x68), struct.pack('<I', arena))
        u.reg_write(UC_X86_REG_ESP, sp)
        success = 0xa75b1d if own else 0xa742e0
        failures = {0xa75981, 0xa75b06} if own else {0xa740a4, 0xa742c9}
        reached = []
        def stop(machine, address, size, data):
            if address == success or address in failures:
                reached.append(address)
                machine.emu_stop()
        u.hook_add(UC_HOOK_CODE, stop)
        u.emu_start(0xa7596b if own else 0xa7408e, 0xa85797, count=50000)
        self.assertEqual(len(reached), 1)
        consumed = struct.unpack('<I', u.mem_read(sp + 0x14, 4))[0] - source
        result = (reached[0] == success, consumed)
        return (*result, bytes(u.mem_read(arena, 512))) if capture else result

    def test_base_appear_packet_full_native_cursor(self):
        desc = local_battle.spawn_unit_body({'uniqid': 900000000, 'msma_id': 777201}, 255)
        body = battle_entities.appear_body(desc, 100, (12445, -671, 15881), team=0,
                                          troops=0, world_id=1, pilot_id=77, letter=1)
        self.assertEqual(self.parse(body, False), (True, len(body)))
        self.assertFalse(self.parse(body[:-1], False)[0])
        self.assertFalse(self.parse(body + b'\0', False)[0])

    def test_player_appear_self_packet_full_native_cursor(self):
        desc = local_battle.spawn_unit_body({'uniqid': 123, 'msma_id': 777001}, 0)
        body = battle_entities.appear_self_body(desc, 1, (12445, -671, 15881), team=0,
                                               troops=0, hp=3425, shield_hp=990)
        self.assertEqual(self.parse(body, True), (True, len(body)))
        self.assertFalse(self.parse(body[:-1], True)[0])
        self.assertFalse(self.parse(body + b'\0', True)[0])

    def test_self_packet_preserves_all_equipment_in_native_descriptor(self):
        unit = {'uniqid': 123, 'msma_id': 777001,
                'equipped_weapons': [777108, 777106, 777103], 'shield': 777104}
        body = battle_entities.appear_self_body(local_battle.spawn_unit_body(unit, 0),
                1, (0, 0, 0), team=0, troops=0, hp=3425, shield_hp=990)
        accepted, consumed, output = self.parse(body, True, capture=True)
        self.assertTrue(accepted)
        self.assertEqual(consumed, 244)
        # Native descriptor begins at output+2; A604E0 names witem_id at +3C.
        self.assertEqual(struct.unpack_from('<5I', output, 2+0x3c),
                         (777108, 777106, 777103, 777104, 0))
