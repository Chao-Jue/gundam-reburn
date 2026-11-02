"""Regression for distinguishing a character controller from its render object."""
import unittest
import probe_battle_entities as probe


class Memory:
    def __init__(self, model=0x4000):
        self.words = {0x1280: 0x2000, 0x2014: 0x3000, 0x1124: model}

    def u32(self, address):
        return self.words.get(address)

    def read(self, address, size):
        return bytes(size) if address == 0x4000 else None


class BattleRenderProbeTest(unittest.TestCase):
    def test_controller_does_not_count_as_a_render_object(self):
        value = probe.render_state(Memory(), 0x1000)
        self.assertEqual(value['controller'], 0x2000)
        self.assertEqual(value['render_object'], 0x4000)
        self.assertIsNotNone(value['render_raw'])

    def test_missing_render_object_is_reported_even_with_controller(self):
        value = probe.render_state(Memory(model=0), 0x1000)
        self.assertEqual(value['controller'], 0x2000)
        self.assertEqual(value['render_object'], 0)
        self.assertIsNone(value['render_raw'])


if __name__ == '__main__':
    unittest.main()
