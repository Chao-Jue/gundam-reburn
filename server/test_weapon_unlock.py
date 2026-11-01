"""武器解锁：新增测试武器、解锁动作、解锁状态持久化。

约定：
- 三把 starter 武器（777101-777103）是唯一默认授予的；
- 新增测试武器（777105-777108）只在下载表里定义，**不自动授予**，必须显式解锁；
- 解锁 = 写进机体记录的 weapons 列表并落盘，重启服务/重登后仍在。
"""
import csv
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import fake_auth
import hangar_experiment as experiment
from hangar import HangarStore

STARTER = [777101, 777102, 777103]
TEST_WEAPONS = [777105, 777106, 777107, 777108]


def table_rows(name):
    body = experiment.table_body(name)
    if body is None:
        raise AssertionError('%s 没有生成表体' % name)
    return list(csv.reader(io.StringIO(body.decode())))[2:]


class WeaponDefinitionTest(unittest.TestCase):
    def test_test_weapons_are_defined_but_not_granted_by_default(self):
        extra = experiment.test_definitions()
        self.assertEqual([w['item_id'] for w in extra], TEST_WEAPONS)

        unit = experiment.gm_unit()
        self.assertEqual([w['item_id'] for w in unit['weapons']], STARTER)
        self.assertEqual(unit['equipped_weapons'], STARTER)

    def test_test_weapons_are_downloadable_and_equippable(self):
        """没在 msma_weapon_set 里的武器，客户端不会放进可装备列表。"""
        item_ids = {int(r[0]) for r in table_rows('item/item.csv')}
        settings = {int(r[0]) for r in table_rows('item/weapon_settings.csv')}
        weapon_set = {int(r[2]) for r in table_rows('msma/msma_weapon_set.csv')}
        self.assertLessEqual(set(TEST_WEAPONS), item_ids)
        self.assertLessEqual(set(TEST_WEAPONS), settings)
        self.assertLessEqual(set(TEST_WEAPONS), weapon_set)

    def test_test_weapons_use_verified_resources_and_known_enums(self):
        settings = {int(r[0]): r for r in table_rows('item/weapon_settings.csv')}
        verified = (2010501, 4010101, 10020101, 2010301, 4010301, 10090101, 2010601)
        for weapon in experiment.test_definitions():
            row = settings[weapon['item_id']]
            # 枚举只用已验证过的三类；资源号必须在本地 icon+vra 都存在的白名单里。
            self.assertIn(row[21], ('SHOTGUN', 'WRESTLE', 'HAND_THROW'))
            self.assertIn(row[30], ('GUN_SINGLE', 'WRESTLE', 'HAND_THROW'))
            self.assertIn(int(row[2]), verified)
            self.assertEqual(row[2], str(weapon['resource']))

    def test_weights_stay_within_experiment_payload(self):
        payload = int(table_rows('msma/msma_settings.csv')[0][52])
        total = sum(int(w['attributes']['重量']) for w in experiment.all_definitions())
        self.assertLessEqual(max(int(w['attributes']['重量'])
                                 for w in experiment.all_definitions()), payload)
        self.assertEqual(payload, 1450)
        self.assertGreater(total, 0)


class WeaponUnlockTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.store = HangarStore(Path(self.folder.name) / 'gm.json')
        self.unit = experiment.gm_unit()
        self.store.replace_units('test', 3, [self.unit])

    def tearDown(self):
        self.folder.cleanup()

    def test_unlock_adds_weapon_and_persists_across_reload(self):
        added = experiment.unlock_weapon(self.store, 'test', 3, self.unit['uniqid'], 777105)
        self.assertTrue(added)

        reloaded = HangarStore(self.store.path).units('test', 3)[0]
        owned = [w['item_id'] for w in reloaded['weapons']]
        self.assertEqual(owned, STARTER + [777105])
        self.assertNotIn(777105, reloaded['equipped_weapons'])

    def test_unlock_is_idempotent(self):
        self.assertTrue(experiment.unlock_weapon(self.store, 'test', 3, self.unit['uniqid'], 777105))
        self.assertFalse(experiment.unlock_weapon(self.store, 'test', 3, self.unit['uniqid'], 777105))
        self.assertEqual([w['item_id'] for w in self.store.units('test', 3)[0]['weapons']],
                         STARTER + [777105])

    def test_db_index_follows_weapon_set_order(self):
        experiment.unlock_weapon(self.store, 'test', 3, self.unit['uniqid'], 777107)
        weapon = self.store.units('test', 3)[0]['weapons'][-1]
        self.assertEqual(weapon['item_id'], 777107)
        self.assertEqual(weapon['db_index'], 5)  # all_definitions 里的下标

    def test_unlocked_weapon_can_be_equipped_and_survives_relogin(self):
        experiment.unlock_weapon(self.store, 'test', 3, self.unit['uniqid'], 777106)
        with patch.object(fake_auth, 'HANGAR_EXPERIMENT_STORE', self.store), \
             patch.object(fake_auth, 'HANGAR_EXPERIMENT', True):
            reply = fake_auth.hall_replies(
                0x0AA5, struct.pack('<QHI', self.unit['uniqid'], 2, 777106), 'test', 3)
            self.assertEqual(struct.unpack_from('<i', reply[0][1])[0], 0)
            body = fake_auth.hall_replies(0x16AC, b'', 'test', 3)[1][1]
            self.assertEqual(struct.unpack_from('<I', body, 110)[0], 777106)  # 槽位 2 = 102+4*2

        reloaded = HangarStore(self.store.path).units('test', 3)[0]
        self.assertEqual(reloaded['equipped_weapons'], [777101, 777102, 777106])

    def test_unlock_rejects_unknown_weapon(self):
        with self.assertRaises(ValueError):
            experiment.unlock_weapon(self.store, 'test', 3, self.unit['uniqid'], 777199)

    def test_unlock_rejects_shield_and_unknown_unit(self):
        with self.assertRaises(ValueError):
            experiment.unlock_weapon(self.store, 'test', 3, self.unit['uniqid'], 777104)
        with self.assertRaises(ValueError):
            experiment.unlock_weapon(self.store, 'test', 3, 1, 777105)

    def test_weapon_cap_is_enforced(self):
        unit = self.store.units('test', 3)[0]
        unit['weapons'] = [{'item_id': 900000 + i, 'db_index': i} for i in range(30)]
        unit['equipped_weapons'] = [0, 0, 0]
        self.store.replace_units('test', 3, [unit])
        with self.assertRaises(ValueError):
            experiment.unlock_weapon(self.store, 'test', 3, unit['uniqid'], 777105)


class WeaponLockTest(unittest.TestCase):
    """反向操作：把已解锁的武器退回未解锁，用于回归"新武器不该默认可用"。"""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.store = HangarStore(Path(self.folder.name) / 'gm.json')
        self.unit = experiment.gm_unit()
        self.store.replace_units('test', 3, [self.unit])

    def tearDown(self):
        self.folder.cleanup()

    def test_new_test_weapons_start_locked(self):
        unit = experiment.gm_unit()
        owned = {w['item_id'] for w in unit['weapons']}
        self.assertEqual(owned, set(STARTER))
        for weapon in experiment.test_definitions():
            self.assertNotIn(weapon['item_id'], owned)

    def test_lock_removes_weapon_and_persists(self):
        experiment.unlock_weapon(self.store, 'test', 3, self.unit['uniqid'], 777105)
        self.assertTrue(experiment.lock_weapon(self.store, 'test', 3, self.unit['uniqid'], 777105))
        reloaded = HangarStore(self.store.path).units('test', 3)[0]
        self.assertEqual([w['item_id'] for w in reloaded['weapons']], STARTER)

    def test_lock_clears_equipped_slot(self):
        experiment.unlock_weapon(self.store, 'test', 3, self.unit['uniqid'], 777106)
        with patch.object(fake_auth, 'HANGAR_EXPERIMENT_STORE', self.store), \
             patch.object(fake_auth, 'HANGAR_EXPERIMENT', True):
            fake_auth.hall_replies(
                0x0AA5, struct.pack('<QHI', self.unit['uniqid'], 1, 777106), 'test', 3)
        self.assertEqual(self.store.units('test', 3)[0]['equipped_weapons'][1], 777106)
        experiment.lock_weapon(self.store, 'test', 3, self.unit['uniqid'], 777106)
        equipped = self.store.units('test', 3)[0]['equipped_weapons']
        self.assertEqual(equipped[1], 0)
        self.assertEqual(equipped[0], 777101)

    def test_lock_unowned_is_noop(self):
        self.assertFalse(experiment.lock_weapon(self.store, 'test', 3, self.unit['uniqid'], 777105))
        self.assertEqual([w['item_id'] for w in self.store.units('test', 3)[0]['weapons']], STARTER)

    def test_lock_rejects_unknown_unit(self):
        with self.assertRaises(ValueError):
            experiment.lock_weapon(self.store, 'test', 3, 1, 777101)


class WeaponUnlockProtocolTest(unittest.TestCase):
    """0x550A msma_weapon_unlock：真实客户端「开发」按钮发出的请求。

    发送端 0xAE4100 定长 0x16=22B（2B 操作码 + 20B 正文）：
    uniqid u64 | item_id u32 | use_gp u32 | use_bc u32。
    """

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.store = HangarStore(Path(self.folder.name) / 'gm.json')
        self.unit = experiment.gm_unit()
        self.store.replace_units('test', 3, [self.unit])
        self.body = struct.pack('<QIII', self.unit['uniqid'], 777105, 0, 0)
        # 别把单元测试的假事件写进生产日志 server/fake_auth.log
        quiet = patch.object(fake_auth, 'log', lambda *a, **k: None)
        quiet.start()
        self.addCleanup(quiet.stop)

    def tearDown(self):
        self.folder.cleanup()

    def _call(self, body):
        with patch.object(fake_auth, 'HANGAR_EXPERIMENT_STORE', self.store), \
             patch.object(fake_auth, 'UNLOCK_REPLY_OVERRIDE', False), \
             patch.object(fake_auth, 'HANGAR_EXPERIMENT', True):
            return fake_auth.hall_replies(0x550A, body, 'test', 3)

    def test_unlock_request_persists_and_replies_ok(self):
        reply = self._call(self.body)
        self.assertEqual(reply[0][0], 0x45E4)
        payload = reply[0][1]
        # 17B：result u32 | uniqid_ms u64 | item_id u32 | db_index s8
        # 处理器 0xAAE1BC 会拿游标与 end 比较，长度必须精确。
        self.assertEqual(len(payload), 17)
        self.assertEqual(struct.unpack_from('<I', payload, 0)[0], 0)
        self.assertEqual(struct.unpack_from('<Q', payload, 4)[0], self.unit['uniqid'])
        self.assertEqual(struct.unpack_from('<I', payload, 12)[0], 777105)
        self.assertEqual(struct.unpack_from('<b', payload, 16)[0], 3)  # all_definitions 下标
        self.assertEqual([w['item_id'] for w in self.store.units('test', 3)[0]['weapons']],
                         STARTER + [777105])

    def test_unlock_request_is_idempotent(self):
        self._call(self.body)
        reply = self._call(self.body)
        self.assertEqual(struct.unpack_from('<i', reply[0][1], 0)[0], 0)
        self.assertEqual(len(self.store.units('test', 3)[0]['weapons']), 4)

    def test_unknown_weapon_reports_failure_without_writing(self):
        reply = self._call(struct.pack('<QIII', self.unit['uniqid'], 777199, 0, 0))
        self.assertEqual(struct.unpack_from('<i', reply[0][1], 0)[0], -1)
        self.assertEqual([w['item_id'] for w in self.store.units('test', 3)[0]['weapons']],
                         STARTER)

    def test_short_body_is_ignored(self):
        self.assertEqual(self._call(b'\x01\x02\x03'), [])

    def test_unlock_opcode_must_be_whitelisted(self):
        """回归：0x550A 不在 HALL_OPS 时，整帧会被丢弃，handler 根本进不来。"""
        self.assertIn(0x550A, fake_auth.HALL_OPS)
        self.assertIn(0xA28F, fake_auth.HALL_OPS)
        self.assertIn(0x34AB, fake_auth.HALL_OPS)


if __name__ == '__main__':
    unittest.main()
