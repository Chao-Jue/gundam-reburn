"""Native attached-effect field selection; excludes effect loading/rendering."""
import csv
import io
import ntpath
import struct
import sys
import unittest
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EIP, UC_X86_REG_EAX

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment


class WeaponEffectNativeTest(unittest.TestCase):
    def effect_path(self, token):
        """Execute 5440D0's prefix/append logic after CSV path normalization."""
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0, 0x1000)
        u.mem_map(0x400000, (len(image)+4095)&~4095)
        u.mem_write(0x400000, image)
        u.mem_map(0x20000000, 0x10000)
        output, source, stack, stop = [0x20001000+i*0x1000 for i in range(4)]
        # B083A0 normalizes relative CSV paths with a .\ prefix, observed in
        # live definitions too. Full B083A0/CSV/string allocation is not run.
        values = {source: '.\\'+token.replace('/', '\\')}
        u.mem_write(source+20, struct.pack('<I', len(values[source])))
        u.mem_write(stack, struct.pack('<3I', stop, output, source))
        u.reg_write(UC_X86_REG_ESP, stack)

        def strings(m, address, size, data):
            if address not in (0x402b20, 0x40ae90):
                return
            sp = m.reg_read(UC_X86_REG_ESP)
            ret, src, count = struct.unpack('<3I', m.mem_read(sp, 12))
            dst = m.reg_read(UC_X86_REG_ECX)
            if address == 0x402b20:
                values[dst] = bytes(m.mem_read(src, count*2)).decode('utf-16-le')
                args = 8
            else:
                values[dst] += values[src]
                args = 12
            m.reg_write(UC_X86_REG_EAX, dst)
            m.reg_write(UC_X86_REG_ESP, sp+4+args)
            m.reg_write(UC_X86_REG_EIP, ret)

        u.hook_add(UC_HOOK_CODE, strings)
        u.emu_start(0x5440d0, stop, count=1000)
        self.assertEqual(u.reg_read(UC_X86_REG_EIP), stop)
        return ntpath.normpath(values[output])

    def test_generated_effect_survives_native_fx_prefix(self):
        for weapon in hangar_experiment.all_definitions():
            if weapon['kind'] == 'WRESTLE':
                path = self.effect_path(weapon['attached_effect'])
                self.assertTrue((ROOT / 'GundamOnline_CHINA_已解密/decrypted' / path).is_file(), path)

    def test_native_effect_selector_uses_separate_state_fields(self):
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        for state, expected in ((0, 0x528), (1, 0x624)):
            with self.subTest(state=state):
                u = Uc(UC_ARCH_X86, UC_MODE_32)
                u.mem_map(0, 0x1000)
                u.mem_map(0x400000, (len(image)+4095)&~4095)
                u.mem_write(0x400000, image)
                u.mem_map(0x20000000, 0x10000)
                obj, table, node, definition, stack, stop = [
                    0x20001000+i*0x1000 for i in range(6)]
                u.mem_write(obj, struct.pack('<I', 0xcb5e54))
                u.mem_write(obj+8, struct.pack('<I', 777106))
                u.mem_write(0x1161f88, struct.pack('<I', table))
                u.mem_write(table+8, struct.pack('<I', table+0x100))
                u.mem_write(node+0x5c, struct.pack('<I', definition))
                u.mem_write(definition+0x974, struct.pack('<I', 0x10))
                u.mem_write(stack, struct.pack('<4I', stop, state, 0, 0))
                u.reg_write(UC_X86_REG_ESP, stack)
                u.reg_write(UC_X86_REG_ECX, obj)
                selected = []

                def external(m, address, size, data):
                    sp = m.reg_read(UC_X86_REG_ESP)
                    if address == 0x85a8c0:
                        ret, output = struct.unpack('<2I', m.mem_read(sp, 8))
                        m.mem_write(output, struct.pack('<I', node))
                        m.reg_write(UC_X86_REG_ESP, sp+12)
                        m.reg_write(UC_X86_REG_EIP, ret)
                    elif address == 0x402a30:
                        source = struct.unpack('<I', m.mem_read(sp+4, 4))[0]
                        selected.append(source-definition)
                        m.emu_stop()

                u.hook_add(UC_HOOK_CODE, external)
                u.emu_start(0x4e2a40, stop, count=2000)
                self.assertEqual(selected, [expected])

    def test_sabers_configure_an_existing_blade_effect_for_both_states(self):
        rows = list(csv.reader(io.StringIO(hangar_experiment.weapon_tables(
            'item/weapon_settings.csv').decode())))[2:]
        assets = ROOT / 'GundamOnline_CHINA_已解密/decrypted'
        for row in rows:
            if row[30] != 'WRESTLE':
                continue
            for column in (60, 62):
                with self.subTest(item=row[0], column=column):
                    self.assertTrue(row[column], 'saber has only its hilt, no attached blade')
                    effect = assets / self.effect_path(row[column])
                    text = effect.read_text(encoding='utf8')
                    self.assertIn('"saber_body"', text)
                    self.assertIn('"s_shot01"', text)
        hilt = assets / 'item/04/0101/model/EM_04_0101_01.dxg'
        self.assertIn(b's_shot01\0', hilt.read_bytes())


if __name__ == '__main__':
    unittest.main()
