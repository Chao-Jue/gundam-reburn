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


if __name__ == '__main__':
    unittest.main()
