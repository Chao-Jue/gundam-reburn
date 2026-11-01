import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import app
from dxg import parse


GM = app.ASSETS / 'chara/01/01/0101/model/MSM_0101_0101_01.dxg'


class MatcherTest(unittest.TestCase):
    def test_gm_real_mesh_and_truncated_data(self):
        data = GM.read_bytes()
        model = parse(data)
        self.assertEqual(len(model['meshes']), 8)
        self.assertGreater(sum(len(m['indices']) for m in model['meshes']), 4500)
        for m in model['meshes']:
            self.assertEqual(len(m['positions']), len(m['normals']))
            self.assertEqual(len(m['positions']) // 3, len(m['uvs']) // 2)
            self.assertLess(max(m['indices']), len(m['positions']) // 3)
        for bad in [b'', data[:100], data[:-100]]:
            with self.assertRaises(ValueError): parse(bad)

    def test_save_reload_keeps_multiple_models_and_variants(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(app, 'SAVE', Path(folder) / 'matches.json'):
            first = {'units': [{'title': '吉姆'}, {'title': '吉姆（金图参考）'}]}
            app.save_match('gm', first)
            app.save_match('other', {'notes': 'keep'})
            self.assertEqual(app.read_matches()['matches']['gm'], first)
            app.save_match('gm', None)
            self.assertEqual(app.read_matches()['matches'], {'other': {'notes': 'keep'}})

    def test_catalog_ids(self):
        models = app.catalog()
        self.assertTrue(any(m['model_id'] == 101010101 and m['key'].endswith('MSM_0101_0101_01.dxg') for m in models))
        self.assertEqual(len({m['key'] for m in models}), len(models))


if __name__ == '__main__': unittest.main()
