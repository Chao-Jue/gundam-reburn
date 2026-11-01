"""装备组（装备记忆）的存储与协议测试。

线上格式全部来自 v5.0.0.33 的实测与反汇编，不猜：
  - 客户端发送端 0xAE5480 `send_msma_equipset_store`，正文 = uniqid u64 + 121B
  - 装备组块序列化器 0xA948C0 / 反序列化器 0xA96750 字段宽度一一对应
  - 回复 0x7172 `recv_msma_equipset_store_r`（处理器 0xAB5F0A）= result 4 + uniqid 8 + 块 121
"""
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import fake_auth
from hangar import (EQUIPSET_NAME_OFFSET, EQUIPSET_NAME_SIZE, EQUIPSET_SLOT_OFFSET,
                    EQUIPSET_WIRE_SIZE, HangarStore, decode_equipset, encode_equipset,
                    unit_add_body)
import hangar_experiment

UNIQID = hangar_experiment.UNIQID


def sample_blob(weapons=(777105, 777102, 777103), shield=777104, name='装备组合1',
                slot=0, a=0x001AF614, b=0x5CDD4DA8):
    """按 0xA948C0 的字段顺序拼一个 121B 装备组块。"""
    blob = bytearray(EQUIPSET_WIRE_SIZE)
    struct.pack_into('<II', blob, 0x00, a, b)
    struct.pack_into('<H', blob, EQUIPSET_SLOT_OFFSET, slot)
    struct.pack_into('<3I', blob, 0x0A, *weapons)
    struct.pack_into('<I', blob, 0x16, shield)
    struct.pack_into('<I', blob, 0x1A, 0)
    encoded = name.encode('utf-8')[:EQUIPSET_NAME_SIZE]
    blob[EQUIPSET_NAME_OFFSET:EQUIPSET_NAME_OFFSET + len(encoded)] = encoded
    return bytes(blob)


class EquipsetCodecTest(unittest.TestCase):
    def test_block_is_121_bytes(self):
        self.assertEqual(len(sample_blob()), 121)
        self.assertEqual(EQUIPSET_WIRE_SIZE, 121)

    def test_decode_reads_every_observed_field(self):
        entry = decode_equipset(sample_blob())
        self.assertEqual(entry['slot'], 0)
        self.assertEqual(entry['name'], '装备组合1')
        self.assertEqual(entry['weapons'], [777105, 777102, 777103])
        self.assertEqual(entry['shield'], 777104)
        self.assertEqual(len(bytes.fromhex(entry['raw'])), 121)

    def test_encode_prefers_raw_and_round_trips(self):
        blob = sample_blob(slot=3, name='装备组成3号')
        entry = decode_equipset(blob)
        self.assertEqual(encode_equipset(entry), blob)

    def test_encode_from_fields_when_raw_missing(self):
        blob = encode_equipset({'slot': 2, 'name': 'ABC', 'weapons': [1, 2, 3],
                                'shield': 4})
        self.assertEqual(len(blob), 121)
        self.assertEqual(struct.unpack_from('<H', blob, EQUIPSET_SLOT_OFFSET)[0], 2)
        self.assertEqual(struct.unpack_from('<3I', blob, 0x0A), (1, 2, 3))
        self.assertEqual(struct.unpack_from('<I', blob, 0x16)[0], 4)
        self.assertTrue(blob[EQUIPSET_NAME_OFFSET:].startswith(b'ABC\x00'))

    def test_rejects_wrong_size(self):
        with self.assertRaises(ValueError):
            decode_equipset(b'\x00' * 120)
        with self.assertRaises(ValueError):
            encode_equipset({'raw': '00' * 120})


class EquipsetStoreTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.store = HangarStore(Path(self.folder.name) / 'gm.json')
        self.store.replace_units('test', 3, [hangar_experiment.gm_unit()])

    def tearDown(self):
        self.folder.cleanup()

    def test_store_persists_across_reload(self):
        stored, entry = self.store.store_equipset(
            'test', 3, UNIQID, sample_blob())
        self.assertEqual(stored, sample_blob())
        self.assertEqual(entry['name'], '装备组合1')
        reloaded = HangarStore(self.store.path)
        sets = reloaded.units('test', 3)[0]['equipsets']
        self.assertEqual(len(sets), 1)
        self.assertEqual(sets[0]['slot'], 0)
        self.assertEqual(sets[0]['weapons'], [777105, 777102, 777103])

    def test_same_slot_overwrites(self):
        self.store.store_equipset('test', 3, UNIQID, sample_blob(name='A'))
        self.store.store_equipset('test', 3, UNIQID, sample_blob(name='B'))
        sets = self.store.units('test', 3)[0]['equipsets']
        self.assertEqual(len(sets), 1)
        self.assertEqual(sets[0]['name'], 'B')

    def test_different_slots_coexist_and_sort(self):
        self.store.store_equipset('test', 3, UNIQID, sample_blob(slot=2, name='C'))
        self.store.store_equipset('test', 3, UNIQID, sample_blob(slot=0, name='A'))
        sets = self.store.units('test', 3)[0]['equipsets']
        self.assertEqual([e['slot'] for e in sets], [0, 2])
        self.assertEqual([e['name'] for e in sets], ['A', 'C'])

    def test_slot_out_of_range_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.store_equipset('test', 3, UNIQID, sample_blob(slot=8))

    def test_unknown_unit_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.store_equipset('test', 3, 123, sample_blob())

    def test_remove_equipset(self):
        self.store.store_equipset('test', 3, UNIQID, sample_blob(slot=1))
        self.assertTrue(self.store.remove_equipset('test', 3, UNIQID, 1))
        self.assertFalse(self.store.remove_equipset('test', 3, UNIQID, 1))
        self.assertEqual(self.store.units('test', 3)[0]['equipsets'], [])

    def test_apply_equipset_sets_loadout(self):
        self.store.store_equipset('test', 3, UNIQID,
                                  sample_blob(weapons=(777101, 777102, 777103),
                                              shield=777104))
        self.store.apply_equipset('test', 3, UNIQID, 0)
        unit = self.store.units('test', 3)[0]
        self.assertEqual(unit['equipped_weapons'], [777101, 777102, 777103])
        self.assertEqual(unit['shield'], 777104)

    def test_apply_equipset_rejects_unowned_weapon(self):
        self.store.store_equipset('test', 3, UNIQID,
                                  sample_blob(weapons=(777108, 777102, 777103)))
        with self.assertRaises(ValueError):
            self.store.apply_equipset('test', 3, UNIQID, 0)

    def test_unit_add_body_carries_equipsets(self):
        self.store.store_equipset('test', 3, UNIQID, sample_blob(slot=0))
        self.store.store_equipset('test', 3, UNIQID, sample_blob(slot=1))
        unit = self.store.units('test', 3)[0]
        body = unit_add_body(unit)
        weapons = unit.get('weapons', [])
        equipset_count_at = 299 + 4 + len(weapons) * 30
        self.assertEqual(struct.unpack_from('<I', body, equipset_count_at)[0], 2)
        self.assertEqual(len(body), equipset_count_at + 4 + 2 * 121)
        # 第一条应当是 slot=0
        first = body[equipset_count_at + 4:equipset_count_at + 4 + 121]
        self.assertEqual(struct.unpack_from('<H', first, EQUIPSET_SLOT_OFFSET)[0], 0)


class EquipsetProtocolTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.store = HangarStore(Path(self.folder.name) / 'gm.json')
        self.store.replace_units('test', 3, [hangar_experiment.gm_unit()])
        quiet = patch.object(fake_auth, 'log', lambda *a, **k: None)
        quiet.start()
        self.addCleanup(quiet.stop)

    def tearDown(self):
        self.folder.cleanup()

    def _call(self, body):
        with patch.object(fake_auth, 'HANGAR_EXPERIMENT_STORE', self.store), \
             patch.object(fake_auth, 'HANGAR_EXPERIMENT', True):
            return fake_auth.hall_replies(0x9527, body, 'test', 3)

    def test_store_request_persists_and_replies(self):
        body = struct.pack('<Q', UNIQID) + sample_blob()
        self.assertEqual(len(body), 129)  # 实测正文长度
        reply = self._call(body)
        self.assertEqual(reply[0][0], 0x7172)
        payload = reply[0][1]
        self.assertEqual(len(payload), 133)
        self.assertEqual(struct.unpack_from('<i', payload, 0)[0], 0)
        self.assertEqual(struct.unpack_from('<Q', payload, 4)[0], UNIQID)
        self.assertEqual(payload[12:], sample_blob())
        self.assertEqual(len(self.store.units('test', 3)[0]['equipsets']), 1)

    def test_short_body_is_ignored(self):
        self.assertEqual(self._call(struct.pack('<Q', UNIQID) + b'\x00' * 8), [])

    def test_failure_reports_negative_result(self):
        body = struct.pack('<Q', 123456) + sample_blob()   # 不存在的机体
        reply = self._call(body)
        self.assertEqual(struct.unpack_from('<i', reply[0][1], 0)[0], -1)

    def test_opcode_must_be_whitelisted(self):
        self.assertIn(0x9527, fake_auth.HALL_OPS)


if __name__ == '__main__':
    unittest.main()
