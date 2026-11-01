import csv
import io
import struct
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

import fake_auth
from hangar import unit_wire, HangarStore
import hangar_experiment as experiment


class IdentityExperimentTest(unittest.TestCase):
    def test_shield_definition_and_one_time_migration(self):
        unit = experiment.gm_unit()
        self.assertEqual(unit.get('shield'), 777104)
        old = dict(unit)
        old.pop('gm_shield_revision', None)
        old['shield'] = 0
        migrated = experiment.upgrade_unarmed_unit(old)
        self.assertEqual(migrated['shield'], 777104)
        migrated['shield'] = 0
        self.assertEqual(experiment.upgrade_unarmed_unit(migrated)['shield'], 0)
        old['shield'] = 123456
        self.assertEqual(experiment.upgrade_unarmed_unit(old)['shield'], 123456)
        old['uniqid'] = 1
        old['shield'] = 0
        self.assertEqual(experiment.upgrade_unarmed_unit(old)['shield'], 0)
        body = experiment.table_body('item/weapon_settings.csv')
        row = next(r for r in csv.reader(io.StringIO(body.decode())) if r[0] == '777104')
        self.assertEqual((row[21], row[30], row[97]), ('SHIELD', 'SHIELD', 'GM_SHIELD_HP'))
        detail = experiment.table_body('item/weapon_battle_detail.csv').decode()
        self.assertIn('SHIELD,GM_SHIELD_HP,990,0', detail)

    def test_weapon_dimensions_and_projectile_dependencies(self):
        def rows(name):
            body = experiment.table_body(name)
            self.assertIsNotNone(body, name)
            return list(csv.reader(io.StringIO(body.decode())))[2:]
        settings = {int(r[0]): r for r in rows('item/weapon_settings.csv')}
        for item, category, mode, ammo in ((777101, 'SHOTGUN', 'GUN_SINGLE', (5, 20)),
                                           (777102, 'WRESTLE', 'WRESTLE', None),
                                           (777103, 'HAND_THROW', 'HAND_THROW', (1, 7))):
            r = settings[item]
            self.assertEqual(r[21], category)
            self.assertEqual(r[30], mode)
            if ammo:
                self.assertEqual(tuple(int(r[c]) for c in (101, 102)), ammo)
        bullets = {int(r[0]): r for r in rows('item/bullet.csv')}
        for item in (777101, 777103):
            self.assertIn(int(settings[item][68]), bullets)
        self.assertEqual(float(bullets[int(settings[777103][68])][11]), 600)
        builds = {int(r[0]): r for r in rows('develop/buildup_weapon.csv')}
        # POWER, STABILITY, LOCKON, RELOAD, RANGE; grenade radius is column10.
        self.assertEqual([int(v) for v in builds[777101][1:7]], [1, 1, 0, 1, 1, 1])
        self.assertEqual(int(builds[777103][10]), 1)

    def test_experiment_weapon_change_survives_relogin_and_is_isolated(self):
        with tempfile.TemporaryDirectory() as folder:
            normal = HangarStore(Path(folder) / 'normal.json')
            experimental = HangarStore(Path(folder) / 'gm.json')
            unit = experiment.gm_unit()
            unit['weapons'].append({'item_id': 987001})
            experimental.replace_units('test', 3, [unit])
            with patch.object(fake_auth, 'HANGAR_STORE', normal), \
                 patch.object(fake_auth, 'HANGAR_EXPERIMENT_STORE', experimental, create=True), \
                 patch.object(fake_auth, 'HANGAR_EXPERIMENT', True):
                reply = fake_auth.hall_replies(0x0AA5, struct.pack('<QHI', unit['uniqid'], 1, 987001), 'test', 3)
                self.assertEqual(struct.unpack_from('<i', reply[0][1])[0], 0)
                added = fake_auth.hall_replies(0x16AC, b'', 'test', 3)[1][1]
                self.assertEqual(struct.unpack_from('<I', added, 106)[0], 987001)
                self.assertEqual(normal.units('test', 3), [])
            self.assertEqual(HangarStore(experimental.path).units('test', 3)[0]['equipped_weapons'][1], 987001)

    def test_three_starter_weapons_have_downloaded_definitions(self):
        unit = experiment.gm_unit()
        self.assertEqual(len(unit['weapons']), 3)
        ids = [w['item_id'] for w in unit['weapons']]
        self.assertEqual(unit['equipped_weapons'], ids)
        self.assertEqual(len(set(ids)), 3)
        tables = {}
        for name in ('item/item.csv', 'item/weapon_settings.csv', 'msma/msma_weapon_set.csv'):
            body = experiment.table_body(name)
            self.assertIsNotNone(body, name)
            tables[name] = list(csv.reader(io.StringIO(body.decode())))[2:]
        # 默认只授予三把 starter；下载表里还有追加的测试武器（必须显式解锁）。
        granted = set(ids)
        defined = {w['item_id'] for w in experiment.all_definitions()}
        self.assertEqual(granted, {w['item_id'] for w in experiment.starter_definitions()})
        self.assertLess(granted, defined)
        self.assertEqual({int(r[0]) for r in tables['item/item.csv']}, defined | {777104})
        self.assertEqual({int(r[0]) for r in tables['item/weapon_settings.csv']}, defined | {777104})
        self.assertEqual({int(r[2]) for r in tables['msma/msma_weapon_set.csv']}, defined)
        definition = list(csv.reader(io.StringIO(experiment.table_body('msma/msma_settings.csv').decode())))[2]
        self.assertEqual({r[0] for r in tables['msma/msma_weapon_set.csv']}, {definition[38]})

    def test_existing_unarmed_seed_is_migrated_without_overwriting_custom_loadout(self):
        with tempfile.TemporaryDirectory() as folder:
            store = HangarStore(Path(folder) / 'gm.json')
            old = experiment.gm_unit()
            old['weapons'], old['equipped_weapons'] = [], [0, 0, 0]
            store.replace_units('test', 3, [old])
            with patch.object(fake_auth, 'HANGAR_EXPERIMENT_STORE', store), \
                 patch.object(fake_auth, 'HANGAR_EXPERIMENT', True):
                fake_auth.hall_replies(0x16AC, b'', 'test', 3)
                migrated = store.units('test', 3)[0]
                self.assertEqual(len(migrated['weapons']), 3)
                migrated['equipped_weapons'][1] = 0
                store.replace_units('test', 3, [migrated])
                fake_auth.hall_replies(0x16AC, b'', 'test', 3)
                self.assertEqual(store.units('test', 3)[0], migrated)

    def test_weapon_weights_use_native_weight_column(self):
        rows = list(csv.reader(io.StringIO(experiment.table_body('item/weapon_settings.csv').decode())))[2:]
        definitions = {w['item_id']: w for w in experiment.all_definitions()}
        for row in rows:
            if row[21] == 'SHIELD':
                self.assertEqual(row[109], '0')
                continue
            self.assertEqual(row[109], definitions[int(row[0])]['attributes']['重量'])

    def test_gm_payload_matches_wiki_and_exceeds_starter_weapon_weight(self):
        definition = list(csv.reader(io.StringIO(experiment.table_body('msma/msma_settings.csv').decode())))[2]
        self.assertEqual(int(definition[52]), 1450)
        weapons = experiment.starter_definitions()
        self.assertLess(sum(int(w['attributes']['重量']) for w in weapons), int(definition[52]))

    def test_gm_supports_ground_and_space(self):
        row = list(csv.reader(io.StringIO(experiment.table_body('msma/msma_settings.csv').decode())))[2]
        # Native terrain label checks row+0x78 and +0x80 together for ground/space.
        self.assertEqual([int(row[c]) for c in (9, 10, 11)], [1, 0, 1])

    def test_gm_speed_templates_follow_native_ui_scale(self):
        rows = list(csv.reader(io.StringIO(experiment.table_body('msma/msma_battle_detail.csv').decode())))[2:]
        values = {row[0]: row for row in rows}
        self.assertIn('MOVE', values)
        self.assertIn('BOOST_SPEED', values)
        speed = float(values['MOVE'][2]) * max(float(values['BOOST_SPEED'][2]), float(values['BOOST_SPEED'][6]))
        self.assertAlmostEqual(speed * 2000 / 1680, 1004, places=3)

    def test_weapon_power_templates_are_defined_and_linked(self):
        body = experiment.table_body('item/weapon_battle_detail.csv')
        self.assertIsNotNone(body)
        details = {r[1]: r for r in list(csv.reader(io.StringIO(body.decode())))[2:]}
        rows = list(csv.reader(io.StringIO(experiment.table_body('item/weapon_settings.csv').decode())))[2:]
        definitions = {w['item_id']: w for w in experiment.all_definitions()}
        for row in rows:
            if row[21] == 'SHIELD':
                self.assertEqual(row[74], '')
                continue
            value = details[row[74]]
            self.assertEqual(value[0], 'POWER')
            self.assertEqual(int(value[2]) * 10, int(definitions[int(row[0])]['attributes']['威力']))

    def test_weapon_power_is_enabled_in_native_ui_visibility_table(self):
        body = experiment.table_body('develop/buildup_weapon.csv')
        self.assertIsNotNone(body)
        masks = {r[0]: r for r in list(csv.reader(io.StringIO(body.decode())))[2:]}
        rows = list(csv.reader(io.StringIO(experiment.table_body('item/weapon_settings.csv').decode())))[2:]
        for row in rows:
            if row[21] == 'SHIELD':
                self.assertEqual(row[64], '')
                continue
            self.assertEqual(masks[row[64]][1], '1')

    def test_gm_base_performance_templates_are_linked(self):
        body = experiment.table_body('msma/msma_battle_detail.csv')
        self.assertIsNotNone(body)
        rows = list(csv.reader(io.StringIO(body.decode())))[2:]
        values = {r[0]: r for r in rows}
        self.assertEqual(values['MAX_HP'][2], '3425')
        self.assertEqual(values['BOOST_GAUGEMAX'][2], '1000')
        definition = list(csv.reader(io.StringIO(experiment.table_body('msma/msma_settings.csv').decode())))[2]
        self.assertEqual(definition[62], values['MAX_HP'][1])
        self.assertEqual(definition[69], values['BOOST_GAUGEMAX'][1])

    def test_starter_deck_control_has_first_slot_in_both_decks(self):
        self.assertEqual(unit_wire(experiment.gm_unit())[90:92], bytes([0, 0]))

    def test_distinct_ids_link_through_downloaded_definition(self):
        rows = list(csv.reader(io.StringIO(experiment.table_body('msma/msma_settings.csv').decode())))
        self.assertEqual(len(rows[2]), 92)
        self.assertEqual([int(x) for x in rows[2][:2]], [777001, 101010101])
        record = unit_wire(experiment.gm_unit())
        self.assertEqual(struct.unpack_from('<I', record, 8)[0], 777001)
        self.assertNotIn(struct.pack('<I', 101010101), record)

    def test_opt_in_only_and_no_persistent_grant(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(fake_auth, 'HANGAR_EXPERIMENT_STORE', HangarStore(Path(folder) / 'gm.json')), \
             patch.object(fake_auth.HANGAR_STORE, 'units', return_value=[]):
            with patch.object(fake_auth, 'HANGAR_EXPERIMENT', False):
                self.assertEqual([op for op, body in fake_auth.hall_replies(0x16AC, b'', 'test')],
                                 [0x2ACF, 0xFCE6])
            with patch.object(fake_auth, 'HANGAR_EXPERIMENT', True):
                self.assertEqual([op for op, body in fake_auth.hall_replies(0x16AC, b'', 'test')],
                                 [0x2ACF, 0xA832, 0xFCE6])
        self.assertIsNone(experiment.table_body('pilot/pilot_form.csv'))


if __name__ == '__main__':
    unittest.main()
