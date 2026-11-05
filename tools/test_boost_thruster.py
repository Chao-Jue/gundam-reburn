"""Check native category-3 thruster IDs against local effect table/resources."""
import csv
import io
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'server'))
import hangar_experiment

class BoostThrusterTest(unittest.TestCase):
    def test_generated_thruster_slots_resolve_in_native_effect_category(self):
        assets=ROOT/'GundamOnline_CHINA_已解密/decrypted'
        effects={}
        for row in csv.reader((assets/'settings/fx.csv').read_text(encoding='utf-8-sig').splitlines()):
            if len(row)>=3 and row[0]=='3':effects[int(row[1])]=row[2]
        rows=list(csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_model.csv').decode())))[2:]
        gm=next(r for r in rows if int(r[0])==hangar_experiment.MODEL_ID)
        # Native53FA30 interleaves columns16..23/24..31 into model+38..74.
        # Native484B20 chooses these IDs and requests effect category3.
        for col in range(16,32):
            with self.subTest(column=col):
                effect=int(gm[col]);self.assertTrue(effect in effects, f"unresolved native fx category3/id{effect}")
                self.assertTrue((assets/effects[effect]).is_file())

if __name__=='__main__':unittest.main()
