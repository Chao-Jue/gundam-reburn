"""机体组（msset /「机体设置01」）的存储与协议测试。

格式来自 v5.0.0.33 实测与反汇编：
  - 请求 0xA76E send_msma_msset_store（发送端 0xAE4ED0），正文 95B = 机体组块
  - 序列化器 0xA94770 / 反序列化器 0xA96600：
      u64 | u16 编号 | u16 槽位 | char[43] 名字 | 4×u64 机体 uniqid | 4×u16
  - 列表请求 0x9A9D（空正文）→ 回 0x356F：u32 count + count×95B（最多 20）
  - 保存回包 0xB8BB：result i32 + 95B = 99B
"""
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import fake_auth
import hangar_experiment
from hangar import (MSSET_FLAGS_OFFSET, MSSET_INDEX_OFFSET, MSSET_MAX_COUNT,
                    MSSET_MS_OFFSET, MSSET_NAME_OFFSET, MSSET_NAME_SIZE,
                    MSSET_SLOT_OFFSET, MSSET_WIRE_SIZE, HangarStore, decode_msset,
                    encode_msset)

UNIQID = hangar_experiment.UNIQID
# 实测抓到的名字区：客户端没初始化，是一段栈垃圾（不是合法 UTF-8）
GARBAGE_NAME = bytes.fromhex(
    '008299001502000028f81a0028ec776c4ed05a5e480b450015020000878e8275178e82758b0058f68803')


def sample_blob(index=0, slot=0, ms=(UNIQID, 0, 0, 0), name=b'', garbage_name=False):
    blob = bytearray(MSSET_WIRE_SIZE)
    struct.pack_into('<H', blob, MSSET_INDEX_OFFSET, index)
    struct.pack_into('<H', blob, MSSET_SLOT_OFFSET, slot)
    struct.pack_into('<4Q', blob, MSSET_MS_OFFSET, *ms)
    raw = GARBAGE_NAME if garbage_name else (
        name.encode('utf-8') if isinstance(name, str) else name)
    raw = raw[:MSSET_NAME_SIZE]
    blob[MSSET_NAME_OFFSET:MSSET_NAME_OFFSET + len(raw)] = raw
    return bytes(blob)


class MssetCodecTest(unittest.TestCase):
    def test_block_is_95_bytes(self):
        self.assertEqual(len(sample_blob()), 95)
        self.assertEqual(MSSET_WIRE_SIZE, 95)

    def test_decode_reads_fields(self):
        entry = decode_msset(sample_blob(index=2, slot=1, ms=(UNIQID, 5, 0, 0)))
        self.assertEqual(entry['index'], 2)
        self.assertEqual(entry['slot'], 1)
        self.assertEqual(entry['ms'], [UNIQID, 5, 0, 0])
        self.assertEqual(entry['flags'], [0, 0, 0, 0])
        self.assertEqual(len(bytes.fromhex(entry['raw'])), 95)

    def test_decode_keeps_valid_name(self):
        entry = decode_msset(sample_blob(name='我的组'.encode('utf-8')))
        self.assertEqual(entry['name'], '我的组')

    def test_garbage_name_is_cleared(self):
        """实测名字区是未初始化栈垃圾：不是合法 UTF-8 就当空名字并清零。"""
        entry = decode_msset(sample_blob(garbage_name=True))
        self.assertEqual(entry['name'], '')
        blob = bytes.fromhex(entry['raw'])
        self.assertEqual(blob[MSSET_NAME_OFFSET:MSSET_NAME_OFFSET + MSSET_NAME_SIZE],
                         bytes(MSSET_NAME_SIZE))
        # 其它字段不受影响
        self.assertEqual(struct.unpack_from('<Q', blob, MSSET_MS_OFFSET)[0], UNIQID)

    def test_encode_round_trips(self):
        blob = sample_blob(index=3, name='ABC')
        self.assertEqual(encode_msset(decode_msset(blob)), blob)

    def test_encode_from_fields(self):
        blob = encode_msset({'index': 1, 'slot': 2, 'name': 'X',
                             'ms': [7, 0, 0, 0], 'flags': [1, 0, 0, 0]})
        self.assertEqual(len(blob), 95)
        self.assertEqual(struct.unpack_from('<H', blob, MSSET_INDEX_OFFSET)[0], 1)
        self.assertEqual(struct.unpack_from('<H', blob, MSSET_SLOT_OFFSET)[0], 2)
        self.assertEqual(struct.unpack_from('<4Q', blob, MSSET_MS_OFFSET), (7, 0, 0, 0))
        self.assertEqual(struct.unpack_from('<4H', blob, MSSET_FLAGS_OFFSET), (1, 0, 0, 0))

    def test_rejects_wrong_size(self):
        with self.assertRaises(ValueError):
            decode_msset(b'\x00' * 94)
        with self.assertRaises(ValueError):
            encode_msset({'raw': '00' * 94})


class MssetStoreTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.store = HangarStore(Path(self.folder.name) / 'gm.json')
        self.store.replace_units('test', 3, [hangar_experiment.gm_unit()])

    def tearDown(self):
        self.folder.cleanup()

    def test_store_and_reload(self):
        self.store.store_msset('test', 3, sample_blob(index=0))
        reloaded = HangarStore(self.store.path)
        sets = reloaded.mssets('test', 3)
        self.assertEqual(len(sets), 1)
        self.assertEqual(sets[0]['index'], 0)
        self.assertEqual(sets[0]['ms'][0], UNIQID)

    def test_same_index_overwrites(self):
        self.store.store_msset('test', 3, sample_blob(index=0, slot=0))
        self.store.store_msset('test', 3, sample_blob(index=0, slot=2))
        sets = self.store.mssets('test', 3)
        self.assertEqual(len(sets), 1)
        self.assertEqual(sets[0]['slot'], 2)

    def test_indexes_sorted(self):
        self.store.store_msset('test', 3, sample_blob(index=5))
        self.store.store_msset('test', 3, sample_blob(index=1))
        self.assertEqual([e['index'] for e in self.store.mssets('test', 3)], [1, 5])

    def test_index_out_of_range(self):
        with self.assertRaises(ValueError):
            self.store.store_msset('test', 3, sample_blob(index=MSSET_MAX_COUNT))

    def test_store_does_not_clobber_units(self):
        self.store.store_msset('test', 3, sample_blob())
        self.assertEqual(len(self.store.units('test', 3)), 1)

    def test_units_write_does_not_clobber_mssets(self):
        self.store.store_msset('test', 3, sample_blob())
        self.store.replace_units('test', 3, [hangar_experiment.gm_unit()])
        self.assertEqual(len(self.store.mssets('test', 3)), 1)

    def test_remove_msset(self):
        self.store.store_msset('test', 3, sample_blob(index=0))
        self.assertTrue(self.store.remove_msset('test', 3, 0))
        self.assertFalse(self.store.remove_msset('test', 3, 0))
        self.assertEqual(self.store.mssets('test', 3), [])

    def test_pilot_isolation(self):
        self.store.store_msset('test', 3, sample_blob())
        self.assertEqual(self.store.mssets('test', 4), [])


class MssetProtocolTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.store = HangarStore(Path(self.folder.name) / 'gm.json')
        self.store.replace_units('test', 3, [hangar_experiment.gm_unit()])
        quiet = patch.object(fake_auth, 'log', lambda *a, **k: None)
        quiet.start()
        self.addCleanup(quiet.stop)

    def tearDown(self):
        self.folder.cleanup()

    def _call(self, op, body):
        with patch.object(fake_auth, 'HANGAR_EXPERIMENT_STORE', self.store), \
             patch.object(fake_auth, 'HANGAR_EXPERIMENT', True):
            return fake_auth.hall_replies(op, body, 'test', 3)

    def test_opcodes_whitelisted(self):
        self.assertIn(0x9A9D, fake_auth.HALL_OPS)
        self.assertIn(0xA76E, fake_auth.HALL_OPS)

    def test_get_empty_list(self):
        reply = self._call(0x9A9D, b'')
        self.assertEqual(reply[0][0], 0x356F)
        self.assertEqual(len(reply[0][1]), 4)
        self.assertEqual(struct.unpack_from('<I', reply[0][1], 0)[0], 0)

    def test_store_then_get_returns_the_group(self):
        reply = self._call(0xA76E, sample_blob(index=0))
        self.assertEqual(reply[0][0], 0xB8BB)
        self.assertEqual(len(reply[0][1]), 99)
        self.assertEqual(struct.unpack_from('<i', reply[0][1], 0)[0], 0)
        listing = self._call(0x9A9D, b'')[0][1]
        self.assertEqual(struct.unpack_from('<I', listing, 0)[0], 1)
        block = listing[4:4 + 95]
        self.assertEqual(struct.unpack_from('<Q', block, MSSET_MS_OFFSET)[0], UNIQID)

    def test_get_caps_at_twenty(self):
        for index in range(MSSET_MAX_COUNT):
            self.store.store_msset('test', 3, sample_blob(index=index))
        listing = self._call(0x9A9D, b'')[0][1]
        count = struct.unpack_from('<I', listing, 0)[0]
        self.assertEqual(count, MSSET_MAX_COUNT)
        self.assertEqual(len(listing), 4 + MSSET_MAX_COUNT * 95)

    def test_short_store_body_is_ignored(self):
        self.assertEqual(self._call(0xA76E, b'\x00' * 10), [])


if __name__ == '__main__':
    unittest.main()
