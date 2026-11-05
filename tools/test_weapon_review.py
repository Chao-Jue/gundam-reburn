"""武器复核数据集装配的回归测试。

用真实 Wiki 缓存 + 客户端资源跑（只读）。断言的是不变量，不是固定数字：
Wiki 更新后行数会变，但「id 自洽 / 图标组唯一 / 边留空」不能变。
"""
import json
import sys
import unittest
from pathlib import Path

tools = Path(__file__).resolve().parent
sys.path.insert(0, str(tools))

import weapon_review

ROOT = tools.parent
SCHEMA = ROOT / 'schemas/weapon_review.schema.json'
needs_wiki = unittest.skipUnless(weapon_review.WIKI.exists(), '需要 Wiki 缓存')


class BuildTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not weapon_review.WIKI.exists():
            raise unittest.SkipTest('需要 Wiki 缓存')
        cls.data, cls.summary = weapon_review.build()

    def test_ids_are_self_consistent(self):
        for key, row in self.data['weapon_data'].items():
            self.assertEqual(row['id'], key)
            self.assertRegex(key, r'^wd_[0-9a-f]{10}$')

    def test_edges_start_empty(self):
        """骨架阶段不允许有任何判定：模型/特效全空，状态全 unknown。"""
        for row in self.data['weapon_data'].values():
            self.assertIsNone(row['model'])
            self.assertEqual(row['effect_groups'], [])
            self.assertEqual(row['status'], 'unknown')
        self.assertEqual(self.data['effect_groups'], {})

    def test_icon_group_created_only_with_image_name(self):
        groups = self.data['icon_pairs']
        with_image = 0
        for row in self.data['weapon_data'].values():
            image = row['source']['image_name']
            if image:
                with_image += 1
                self.assertIsNotNone(row['icon_pair'])
                self.assertIn(row['icon_pair'], groups)
                self.assertEqual(groups[row['icon_pair']]['evidence']['source_ref'], image)
            else:
                self.assertIsNone(row['icon_pair'])
        self.assertEqual(len(groups), self.summary['icon_groups'])
        self.assertGreater(with_image, 0)

    def test_summary_adds_up(self):
        rows = len(self.data['weapon_data'])
        self.assertEqual(rows, self.summary['rows'])
        self.assertEqual(rows, self.summary['rows_with_icon'] + self.summary['rows_without_icon'])
        self.assertEqual(self.summary['models'], len(self.data['models']))
        self.assertEqual(self.summary['units_with_weapons'] + self.summary['units_without_weapons'],
                         len(self.summary['empty_unit_titles']) + self.summary['units_with_weapons'])

    def test_models_carry_client_facts(self):
        parsed = 0
        for key, model in self.data['models'].items():
            self.assertRegex(key, r'^\d{8}$')
            self.assertTrue(model['dxg'].startswith('item/'))
            self.assertIsInstance(model['resource'], int)
            self.assertIsInstance(model['sockets'], list)
            if model['mesh']:
                parsed += 1
                self.assertEqual(model['sockets'], list(dict.fromkeys(model['sockets'])))
        self.assertGreater(parsed, 0)
        self.assertEqual(len(self.summary['model_failures']), len(self.data['models']) - parsed)

    def test_top_level_matches_schema(self):
        schema = json.loads(SCHEMA.read_text('utf8'))
        # 数据里的每个键都必须在 schema 里声明过（顶层不允许 additionalProperties）
        self.assertEqual(set(self.data) - set(schema['properties']), set())
        self.assertEqual(set(schema['required']) - set(self.data), set())
        self.assertEqual(self.data['schema_version'], 1)


class HelperTest(unittest.TestCase):
    def test_short_id_is_stable_and_distinct(self):
        a = weapon_review.short_id('wd', '高达OL吉姆|0')
        self.assertEqual(a, weapon_review.short_id('wd', '高达OL吉姆|0'))
        self.assertNotEqual(a, weapon_review.short_id('wd', '高达OL吉姆|1'))

    def test_image_name_takes_first_non_empty(self):
        weapon = {'attributes': {'图片名称(png)': '', '图片名称2(png)': '吉翁光束刀3'}}
        self.assertEqual(weapon_review.image_name(weapon), '吉翁光束刀3')
        self.assertIsNone(weapon_review.image_name({'attributes': {}}))


if __name__ == '__main__':
    unittest.main()


class IconLayerTest(unittest.TestCase):
    def test_battle_name_only_replaces_prefix(self):
        import weapon_icon_layer as layer
        self.assertEqual(layer.battle_from_hangar('s02010601'), 'b02010601')
        self.assertEqual(layer.battle_from_hangar('s04010101'), 'b04010101')
        self.assertIsNone(layer.battle_from_hangar('x0101'))

    def test_model_from_icon(self):
        import weapon_icon_layer as layer
        self.assertEqual(layer.model_from_icon('s02010601'), '02010601')
        self.assertIsNone(layer.model_from_icon('s123'))
        self.assertIsNone(layer.model_from_icon('sabcdefgh'))

    def test_match_icons_offline(self):
        """不联网：把 URL 查询、下载、客户端索引都替换掉，只验证拼装逻辑。"""
        import tempfile
        import numpy as np
        from PIL import Image
        import weapon_icon_layer as layer

        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)

            def fake_urls(names, batch=10, timeout=40):
                return {n: 'http://example/' + n for n in names}

            def fake_fetch(name, url, target):
                target.mkdir(parents=True, exist_ok=True)
                path = target / layer.icon_key(name)
                image = Image.new('RGB', (96, 48), (10, 40, 90))
                image.paste((220, 220, 220), (20, 14, 76, 34))
                image.save(path, 'PNG')
                return path

            def fake_index(assets, cache=None, subfolder='interface/icon/item/s', size=(32, 16)):
                name = 's02010601.dds' if 'item/s' in subfolder else 'b02010601.dds'
                return [{'name': name, 'vector': np.zeros(layer.DESCRIPTOR_SIZE, np.float32)}]

            original = (layer.wiki_urls, layer.fetch_icon, layer.client_index)
            layer.wiki_urls, layer.fetch_icon, layer.client_index = fake_urls, fake_fetch, fake_index
            try:
                result, stats = layer.match_icons(['测试武器1'], Path('.'), folder, top=1, battle_top=1)
            finally:
                layer.wiki_urls, layer.fetch_icon, layer.client_index = original

        self.assertEqual(stats['downloaded'], 1)
        payload = result['测试武器1']
        self.assertEqual(payload['candidates'][0]['hangar'], 'interface/icon/item/s/s02010601.dds')
        self.assertEqual(payload['candidates'][0]['model'], '02010601')
        self.assertEqual(payload['battle_candidates'][0]['battle'],
                         'interface/icon/battle/b/b02010601.dds')

    def test_accept_icon_propagates_model_and_keeps_confirmed(self):
        dataset = {
            'models': {'02010601': {'dxg': 'item/02/0106/model/EM_02_0106_01.dxg', 'resource': 2010601}},
            'icon_pairs': {
                'ip_a': {'hangar': None, 'battle': None, 'status': 'candidate',
                         'evidence': {'source_ref': '测试图标', 'source': 'icon_similarity'},
                         'candidates': [{'hangar': 'interface/icon/item/s/s02010601.dds', 'score': 0.01}]},
            },
            'effect_groups': {},
            'weapon_data': {
                'wd_1': {'id': 'wd_1', 'model': None, 'icon_pair': 'ip_a', 'effect_groups': [],
                         'status': 'unknown'},
                'wd_2': {'id': 'wd_2', 'model': None, 'icon_pair': None, 'effect_groups': [],
                         'status': 'unknown'},
            },
            'review_log': [],
        }
        affected, model = weapon_review.accept_icon(
            dataset, 'ip_a', 'interface/icon/item/s/s02010601.dds', None)
        self.assertEqual((affected, model), (1, '02010601'))
        self.assertEqual(dataset['weapon_data']['wd_1']['model'], '02010601')
        self.assertIsNone(dataset['weapon_data']['wd_2']['model'])
        self.assertEqual(dataset['icon_pairs']['ip_a']['status'], 'confirmed')
        self.assertEqual(dataset['weapon_data']['wd_1']['status'], 'candidate')
        self.assertTrue(dataset['review_log'])

    def test_accept_icon_without_matching_model_leaves_model_empty(self):
        dataset = {
            'models': {},
            'icon_pairs': {'ip_b': {'hangar': None, 'battle': None, 'status': 'candidate',
                                    'evidence': {'source_ref': '测试'}}},
            'effect_groups': {},
            'weapon_data': {'wd_3': {'id': 'wd_3', 'model': None, 'icon_pair': 'ip_b',
                                     'effect_groups': [], 'status': 'unknown'}},
            'review_log': [],
        }
        affected, model = weapon_review.accept_icon(dataset, 'ip_b', None, None)
        self.assertEqual((affected, model), (1, None))
        self.assertIsNone(dataset['weapon_data']['wd_3']['model'])
        self.assertEqual(dataset['icon_pairs']['ip_b']['status'], 'unknown')


class ImportCsvTest(unittest.TestCase):
    def _dataset(self):
        return {
            'models': {'02010601': {'dxg': 'item/02/0106/model/EM_02_0106_01.dxg', 'resource': 2010601}},
            'icon_pairs': {
                'ip_x': {'hangar': None, 'battle': None, 'status': 'candidate',
                         'evidence': {'source_ref': '某图标'}, 'candidates': []},
                'ip_mix': {'hangar': None, 'battle': None, 'status': 'candidate',
                           'evidence': {'source_ref': '混合图标'}, 'candidates': []},
            },
            'effect_groups': {},
            'weapon_data': {
                'wd_a': {'id': 'wd_a', 'name': '枪A', 'model': None, 'icon_pair': 'ip_x',
                         'effect_groups': [], 'status': 'unknown',
                         'source': {'wiki_title': '页A', 'row_index': 0, 'image_name': '某图标'}},
                'wd_b': {'id': 'wd_b', 'name': '枪B', 'model': None, 'icon_pair': 'ip_mix',
                         'effect_groups': [], 'status': 'unknown',
                         'source': {'wiki_title': '页A', 'row_index': 1, 'image_name': '混合图标'}},
                'wd_c': {'id': 'wd_c', 'name': '枪C', 'model': None, 'icon_pair': 'ip_mix',
                         'effect_groups': [], 'status': 'unknown',
                         'source': {'wiki_title': '页A', 'row_index': 2, 'image_name': '混合图标'}},
            },
            'review_log': [],
        }

    def test_import_sets_client_id_model_and_icon(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / 'interface/icon/item/s').mkdir(parents=True)
            (tmp / 'interface/icon/item/s/s02010601.dds').write_bytes(b'x')
            (tmp / 'interface/icon/battle/b').mkdir(parents=True)
            (tmp / 'interface/icon/battle/b/b02010601.dds').write_bytes(b'x')
            csv_path = tmp / 'table.csv'
            csv_path.write_bytes(
                '国服页名,行序,武装名,客户端号,状态\n页A,1,枪A,02010601,已对上\n'
                '页A,2,枪B,02010601,已对上\n页A,3,枪C,99999999,已对上\n'.encode('gbk'))
            dataset = self._dataset()
            stats = weapon_review.import_client_ids(dataset, csv_path, assets=tmp)

        self.assertEqual(stats['matched'], 3)
        self.assertEqual(dataset['weapon_data']['wd_a']['client_id'], '02010601')
        self.assertEqual(dataset['weapon_data']['wd_a']['model'], '02010601')
        # 组内号唯一 → 图标写回并确认
        self.assertEqual(dataset['icon_pairs']['ip_x']['hangar'],
                         'interface/icon/item/s/s02010601.dds')
        self.assertEqual(dataset['icon_pairs']['ip_x']['battle'],
                         'interface/icon/battle/b/b02010601.dds')
        self.assertEqual(dataset['icon_pairs']['ip_x']['status'], 'confirmed')
        # 组内号不唯一 → 记冲突，绝不猜一个
        self.assertEqual(dataset['icon_pairs']['ip_mix']['status'], 'conflict')
        self.assertIsNone(dataset['icon_pairs']['ip_mix']['hangar'])

    def test_import_skips_name_mismatch_and_missing_id(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            dataset = self._dataset()
            csv_path = tmp / 'table.csv'
            csv_path.write_bytes(
                '国服页名,行序,武装名,客户端号,状态\n页A,1,完全不同的名字,02010601,已对上\n'
                '页A,2,枪B,,待定\n'.encode('gbk'))
            stats = weapon_review.import_client_ids(dataset, csv_path, assets=tmp)
        self.assertEqual(stats['matched'], 0)
        self.assertEqual(stats['name_mismatch'], 1)
        self.assertEqual(stats['no_id'], 1)
        self.assertIsNone(dataset['weapon_data']['wd_a'].get('client_id'))


class FillIconsTest(unittest.TestCase):
    def test_fill_icons_by_client_id_creates_group_and_skips_missing_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / 'interface/icon/item/s').mkdir(parents=True)
            (tmp / 'interface/icon/item/s/s02010601.dds').write_bytes(b'x')
            dataset = {
                'models': {}, 'effect_groups': {}, 'review_log': [],
                'icon_pairs': {},
                'weapon_data': {
                    'a': {'id': 'a', 'client_id': '02010601', 'icon_pair': None,
                          'model': None, 'effect_groups': [], 'status': 'unknown'},
                    'b': {'id': 'b', 'client_id': '99999999', 'icon_pair': None,
                          'model': None, 'effect_groups': [], 'status': 'unknown'},
                    'c': {'id': 'c', 'client_id': None, 'icon_pair': None,
                          'model': None, 'effect_groups': [], 'status': 'unknown'},
                },
            }
            created, assigned = weapon_review.fill_icons_by_client_id(dataset, assets=tmp)
        self.assertEqual((created, assigned), (1, 1))
        self.assertEqual(dataset['weapon_data']['a']['icon_pair'], 'ip_id_02010601')
        self.assertEqual(dataset['icon_pairs']['ip_id_02010601']['status'], 'confirmed')
        # 没有图标文件、没有客户端号的一律不动，不猜
        self.assertIsNone(dataset['weapon_data']['b']['icon_pair'])
        self.assertIsNone(dataset['weapon_data']['c']['icon_pair'])
