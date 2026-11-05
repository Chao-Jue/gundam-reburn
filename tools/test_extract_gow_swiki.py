"""「各種検証」提取器的回归测试（不依赖存档 HTML，用内联小样本）。"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import extract_gow_swiki as gow

HTML = '''
<h3>リロード時間</h3>
<p>（1000－リロード値）/ 100 ＝ リロード時間（ｓ）</p>
<table><tr><th>リロード値</th><th>リロード時間</th></tr>
<tr><td>400</td><td>6.0s</td></tr><tr><td>700</td><td>3.0s</td></tr></table>
<h3>連射速度</h3>
<table><tr><th>連射速度</th><th>1発撃つフレーム</th></tr>
<tr><td>1316~1328</td><td>20F</td></tr></table>
<h3>各種武装弾速（2014/7/9以降）</h3>
<table><tr><th>使用武器（MS）</th><th>着弾までのフレーム数</th><th>弾速[m/s]</th></tr>
<tr><td>[ビ]強襲BR</td><td>22F</td><td>1364</td></tr></table>
'''


class ExtractTest(unittest.TestCase):
    def test_tables_are_split_by_section(self):
        tables = gow.parse_tables(HTML)
        self.assertEqual([t['section'] for t in tables],
                         ['リロード時間', '連射速度', '各種武装弾速（2014/7/9以降）'])

    def test_reload_formula_matches_measured_table(self):
        # 原文：(1000 - 装填性能) / 100 = 秒
        self.assertEqual(gow.reload_seconds(400), 6.0)
        self.assertEqual(gow.reload_seconds(540), 4.6)
        curve = gow.reload_curve(gow.parse_tables(HTML))
        self.assertEqual(len(curve), 2)
        for point in curve:
            self.assertAlmostEqual(point['formula_seconds'], point['seconds'], places=2)

    def test_rate_of_fire_and_bullet_speed(self):
        tables = gow.parse_tables(HTML)
        rof = gow.rate_of_fire_curve(tables)
        self.assertEqual(rof[0]['frames_per_shot'], 20)
        self.assertEqual(rof[0]['shots_per_second'], 3.0)
        speeds = gow.bullet_speeds(tables)
        self.assertEqual(speeds[0]['speed_mps'], 1364.0)
        self.assertEqual(gow.shots_per_second(0), None)


if __name__ == '__main__':
    unittest.main()
