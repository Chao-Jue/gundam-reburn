import struct
import unittest
from probe_deployment_state import snapshot


class DeploymentProbeTest(unittest.TestCase):
    def test_existing_base_character_is_distinguished_from_missing_map_marker(self):
        values = {0x116C24C: 0x2000, 0x116C250: 0x205c,
                  0x1162000: 0x3000, 0x3004: 0x4000, 0x4004: 0x5000,
                  0x5015: 0, 0x500c: 27000, 0x5010: 0x6000, 0x6000: 0x7000,
                  0x7000: 0x8000, 0x7ffc: 0x9000, 0x900c: 0xa000}
        post = bytearray(92)
        struct.pack_into('<I', post, 0x38, 27000)

        class Memory:
            def u32(self, address):
                return values.get(address)
            u8 = u32
            def read(self, address, count):
                return {0x2000: bytes(post), 0xa008: b'.?AVCChara@@\0'}.get(address)

        result = snapshot(Memory())
        self.assertEqual(result['base_characters'],
                         [{'entity_id': 27000, 'actor': 0x7000, 'class': '.?AVCChara@@'}])
        self.assertNotIn('maps', result)  # no map owner in this fixture
        values[0x6000] = 0
        self.assertEqual(snapshot(Memory())['base_characters'][0]['actor'], 0)


if __name__ == '__main__':
    unittest.main()
