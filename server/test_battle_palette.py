import unittest
import hangar_experiment


class BattlePaletteTest(unittest.TestCase):
    def test_experiment_autoexec_supplies_nontransparent_team_colors(self):
        body = hangar_experiment.table_body('autoexec_sv.cfg')
        self.assertIsNotNone(body, 'experiment must supply missing current-client UI palette keys')
        rows = [line.split(',') for line in body.decode('utf8', errors='replace').splitlines()]
        values = {r[0]: [int(v) for v in r[1:5]] for r in rows
                  if r[0] in ('wnd_eff_ui_color', 'wnd_zeon_ui_color')}
        self.assertEqual(values, {'wnd_eff_ui_color': [255, 51, 170, 255],
                                  'wnd_zeon_ui_color': [255, 255, 68, 68]})
