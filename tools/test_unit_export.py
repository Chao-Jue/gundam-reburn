"""机体级导出的回归测试：纯归并逻辑，不读真实资产。"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import unit_export


def tiny_inputs():
    units = [
        {'title': '页A', 'revision_id': 1, 'source_url': 'u1'},
        {'title': '页B', 'revision_id': 2, 'source_url': 'u2'},
        {'title': '页C', 'revision_id': 3, 'source_url': 'u3'},
    ]
    images = {'images': {'页A': {'url': 'http://img/a.png'}}}
    matches = {
        'm1': {'model_path': 'chara/x/MSM_01.dxg', 'model_id': 101,
               'model_sha256': 'abc', 'units': [{'title': '页A'}]},
    }
    dataset = {
        'models': {'02010601': {'dxg': 'item/02/0106/model/EM.dxg', 'mesh': 'M',
                                'sockets': ['s_shot01']}},
        'icon_pairs': {
            'ip_x': {'hangar': 'interface/icon/item/s/s02010601.dds',
                     'battle': None, 'status': 'confirmed',
                     'evidence': {'source': 'import'}},
            'ip_pending': {'hangar': None, 'battle': None, 'status': 'candidate',
                           'evidence': {'source': 'icon_similarity'}},
        },
        'weapon_data': {
            'w1': {'name': '枪1', 'attributes': {'射击模式': '单发'},
                   'client_id': '02010601', 'model': '02010601', 'icon_pair': 'ip_x',
                   'status': 'candidate', 'source': {'wiki_title': '页A', 'row_index': 0}},
            'w2': {'name': '枪2', 'attributes': {},
                   'client_id': '99999999', 'model': None, 'icon_pair': 'ip_pending',
                   'status': 'unknown', 'source': {'wiki_title': '页A', 'row_index': 1}},
            'w3': {'name': '', 'attributes': {},
                   'client_id': None, 'model': None, 'icon_pair': None,
                   'status': 'unknown', 'source': {'wiki_title': '页C', 'row_index': 0}},
        },
    }
    return units, images, matches, dataset


class UnitExportTest(unittest.TestCase):
    def test_units_carry_model_weapons_and_icons(self):
        units, images, matches, dataset = tiny_inputs()
        records, stats = unit_export.build_units(units, images, matches, dataset)
        self.assertEqual(stats['units'], 3)
        self.assertEqual(stats['weapons'], 3)
        self.assertEqual(stats['with_client_id'], 2)
        self.assertEqual(stats['with_model'], 1)
        self.assertEqual(stats['with_icons'], 1)
        self.assertEqual(stats['units_with_model'], 1)
        self.assertEqual(stats['units_with_portrait'], 1)

        page_a = records[0]
        self.assertEqual(page_a['page'], '页A')
        self.assertEqual(page_a['unit_model']['model_path'], 'chara/x/MSM_01.dxg')
        self.assertEqual(page_a['portrait_url'], 'http://img/a.png')
        self.assertEqual(len(page_a['weapons']), 2)
        first = page_a['weapons'][0]
        self.assertEqual(first['row'], 1)
        self.assertEqual(first['model']['sockets'], ['s_shot01'])
        self.assertEqual(first['icons']['hangar'], 'interface/icon/item/s/s02010601.dds')
        # 未确认的组不能把图标带出来
        self.assertIsNone(page_a['weapons'][1]['icons'])

    def test_unit_without_weapons_still_listed(self):
        units, images, matches, dataset = tiny_inputs()
        records, _ = unit_export.build_units(units, images, matches, dataset)
        page_b = next(r for r in records if r['page'] == '页B')
        self.assertEqual(page_b['weapons'], [])
        self.assertEqual(page_b['counts']['weapons'], 0)
        self.assertIsNone(page_b['unit_model'])


if __name__ == '__main__':
    unittest.main()
