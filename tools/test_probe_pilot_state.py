import unittest

from probe_pilot_state import snapshot, fmt


class FakeReader:
    def __init__(self, values):
        self.values = values

    def u32(self, address):
        return self.values.get(address)

    u8 = u16 = u64 = u32


class SceneProbeTest(unittest.TestCase):
    def test_gm_definition_reads_model_from_map_value(self):
        table, head, node = 0x20000000, 0x21000000, 0x22000000
        reader = FakeReader({0x1161F94: table, table + 8: head, table + 12: 1,
                             head + 4: node, node + 0x341: 0,
                             node + 0x10: 777001, node + 0x18: 777001,
                             node + 0x1C: 101010101})
        state = snapshot(reader)
        self.assertEqual(state['gm_definition_model'], 101010101)
        self.assertEqual(state['gm_definition_id'], 777001)

    def test_scene_comes_from_manager_not_waiting_window(self):
        game, manager, scene, wait = 0x20000000, 0x21000000, 0x22000000, 0x23000000
        reader = FakeReader({
            0x1161F28: game, game: 9, game + 0x1061C: wait,
            wait: 0xD6837C, wait + 0x164: 0,
            0x1161F7C: manager, manager: 0xDF8334,
            manager + 4: scene, manager + 8: 6,
            manager + 12: 0, manager + 16: 4,
            scene: 0xDFA070, scene + 4: 2,
        })
        state = snapshot(reader)
        self.assertEqual(state['scene'], scene)
        self.assertEqual(state['scene_vt'], 0xDFA070)
        self.assertEqual(state['waiting_window'], wait)
        self.assertEqual(state['scene_id'], 6)
        self.assertEqual(state['game_state'], 9)
        self.assertIn('scene_id=6', fmt(state))


if __name__ == '__main__':
    unittest.main()
