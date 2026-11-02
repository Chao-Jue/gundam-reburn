"""Equipment probe handles normal, unarmed and unreadable states."""
import unittest
from probe_battle_weapons import weapon_state, weapon_visuals


class Memory:
    def __init__(self, words=None):
        self.words = words or {}

    def u32(self, address):
        return self.words.get(address)

    u8 = u32

    def read(self, address, size):
        return None


class WeaponProbeTest(unittest.TestCase):
    def test_component_absent_or_unreadable(self):
        for value in (0, None):
            self.assertEqual(weapon_state(Memory({0x135c: value}), 0x1000),
                             {'component': value, 'slots': []})

    def test_three_inline_slots_and_definition_resources(self):
        words = {0x135c: 0x2000, 0x2ea0: 1, 0x3318: 0}
        for i in range(3):
            slot = 0x2000 + 0x144 + i * 0x474
            definition = 0x10000 + i * 0x1000
            words.update({slot: 777101+i, slot+4: definition, slot+8: i,
                          slot+0xc: 0, definition+4: 2010501+i,
                          definition+8: 2010501+i, definition+12: 2010501+i,
                          definition+0x974: 1})
        value = weapon_state(Memory(words), 0x1000)
        self.assertEqual(value['effective_equip_index'], 1)
        self.assertEqual([s['item_id'] for s in value['slots']], [777101,777102,777103])
        self.assertEqual(value['slots'][0]['resources'], [2010501]*3)
        self.assertNotIn('model_handles', value['slots'][0],
                         '47D450 writes protected scalar storage, not model handles')

    def test_alternate_index_is_not_a_fourth_normal_slot(self):
        value = weapon_state(Memory({0x135c: 0x2000, 0x2ea0: 2, 0x3318: 1}), 0x1000)
        self.assertEqual(value['effective_equip_index'], -1)
        self.assertEqual(len(value['slots']), 3)
        self.assertIsNone(value['slots'][0]['resources'])

    def test_visual_manager_list_and_cycle_are_bounded(self):
        words = {0x10b4: 0x2000, 0x2010: 0x3000, 0x3000: 0x4000,
                 0x4000: 0x3000, 0x4008: 0x5000, 0x5000: 0xcb5ecc,
                 0x5008: 777108}
        value = weapon_visuals(Memory(words), 0x1000)
        self.assertEqual(value['objects'][0]['item_id'], 777108)
        self.assertFalse(value['truncated'])
        words[0x4000] = 0x4000
        value = weapon_visuals(Memory(words), 0x1000)
        self.assertTrue(value['truncated'])
        self.assertEqual(len(value['objects']), 1)

    def test_missing_visual_manager(self):
        self.assertEqual(weapon_visuals(Memory(), 0x1000),
                         {'manager': None, 'objects': []})
