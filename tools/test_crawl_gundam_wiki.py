import unittest
from crawl_gundam_wiki import parse_unit, complete_catalog


class WikiParserTest(unittest.TestCase):
    def test_category_only_unit_is_not_silently_dropped(self):
        catalog = {'敢达OL吉姆指挥轻装型机体数据': {
            'fullurl': 'https://example.test/data',
            'printouts': {'名称': ['吉姆指挥轻装型'], 'COST': ['300']}}}
        units = complete_catalog([], catalog)
        self.assertEqual(units[0]['stats']['COST'], '300')
        self.assertEqual(units[0]['data_completeness'], 'catalog_only')
        self.assertEqual(len(complete_catalog(units, catalog)), 1)

    def test_nested_values_and_gold_restrictions_survive(self):
        text = '''{{高达OL基础性能|名称=吉姆|COST=200|装甲=3425}}
{{高达OL武器模板|武器名称=[[光束军刀|军刀]]|是否金限=0|威力={{值|100|200}}}}
{{高达OL武器插入行|武器名称=火箭炮|是否金限=1|重量=600}}
<!-- {{武器|武器名称=忽略}} -->'''
        unit = parse_unit('吉姆', 'source', 123, text)
        self.assertEqual(unit['stats']['COST'], '200')
        self.assertEqual(len(unit['weapons']), 2)
        self.assertEqual(unit['weapons'][0]['attributes']['威力'], '{{值|100|200}}')
        self.assertFalse(unit['weapons'][0]['gold_only'])
        self.assertTrue(unit['weapons'][1]['gold_only'])
        self.assertIsNone(unit['client_unit_id'])

    def test_legacy_tables_are_preserved_without_inventing_weapon_fields(self):
        unit = parse_unit('旧页面', 'source', 1, '{| class="wikitable"\n! 武器 !! 威力\n|-\n| 机枪 || 550\n|}')
        self.assertEqual(unit['tables'][0]['rows'], [['武器', '威力'], ['机枪', '550']])
        self.assertEqual(unit['weapons'], [])


if __name__ == '__main__':
    unittest.main()
