"""Current client initialization contract for deck budget and unit energy."""
import csv
import io
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import fake_auth
import hangar_experiment as experiment
from emulate_wire_reader import decode


class ReadinessNativeTest(unittest.TestCase):
    def test_experiment_deck_budget_survives_actual_pilot_detail_reader(self):
        with patch.object(fake_auth, 'HANGAR_EXPERIMENT', True):
            body = fake_auth.pilot_select_body()
        ok, count, out = decode(0xa95230, body[28:28+29514], 0x9000)
        # Stored image consumes22568; live server's established detail is29514.
        # This check proves the fixed prefix only, not live whole-packet parity.
        self.assertEqual((ok, count), (1, 22568))
        self.assertEqual(struct.unpack_from('<H', out, 24)[0], 1200)
        self.assertGreaterEqual(struct.unpack_from('<H', out, 24)[0],
                                experiment.gm_unit()['cost'])

    def test_energy_capacity_template_matches_owned_current_energy(self):
        def rows(name):
            return list(csv.reader(io.StringIO(experiment.table_body(name).decode())))[2:]
        settings = rows('msma/msma_settings.csv')[0]
        energy = next((r for r in rows('msma/msma_battle_detail.csv')
                       if r[0] == 'ENERGY' and r[1] == settings[64]), None)
        self.assertIsNotNone(energy)
        self.assertEqual(int(energy[2]), 100)
        self.assertLessEqual(experiment.gm_unit()['energy'], int(energy[2]))


if __name__ == '__main__':
    unittest.main()
