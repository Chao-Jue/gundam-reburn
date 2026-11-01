"""Exercise real weapon state resource selection, stopping before asset loading."""
import csv
import io
from pathlib import Path
import struct
import sys
import unittest
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_ECX

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import hangar_experiment as experiment


class ActionResourceNativeTest(unittest.TestCase):
    def test_all_selected_model_states_have_local_resources(self):
        image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
        rows = list(csv.reader(io.StringIO(experiment.table_body(
            'item/weapon_settings.csv').decode())))[2:]
        for row in rows:
            base = int(row[2])
            for flags, alt, third in ((0, False, False), (0, True, False), (4, False, True)):
                with self.subTest(item=row[0], flags=flags, alt=alt, third=third):
                    u = Uc(UC_ARCH_X86, UC_MODE_32)
                    u.mem_map(0, 0x1000)
                    u.mem_map(0x400000, (len(image)+4095)&~4095)
                    u.mem_write(0x400000, image)
                    u.mem_map(0x20000000, 0x20000)
                    obj, item, weapon, vt, sp, end = [0x20001000+i*0x1000 for i in range(6)]
                    u.mem_write(obj, struct.pack('<I', vt))
                    u.mem_write(obj+0x10, struct.pack('<I', item))
                    u.mem_write(item+0x4c, struct.pack('<I', weapon))
                    u.mem_write(weapon+4, struct.pack('<III', *(int(row[c] or 0) for c in (2,3,4))))
                    u.mem_write(weapon+0x974, struct.pack('<I', flags))
                    for offset, value in ((0x50, alt), (0x54, third), (0x58, alt)):
                        code = vt+0x100+offset*16
                        u.mem_write(vt+offset, struct.pack('<I', code))
                        u.mem_write(code, b'\xb8'+struct.pack('<I', int(value))+b'\xc3')
                    u.mem_write(sp, struct.pack('<II', end, obj+0x100))
                    u.reg_write(UC_X86_REG_ESP, sp)
                    u.reg_write(UC_X86_REG_ECX, obj)
                    seen = []

                    def capture(m, address, size, data):
                        if address == 0x4e16c0:
                            p = m.reg_read(UC_X86_REG_ESP)
                            seen.append(struct.unpack('<I', m.mem_read(p+4, 4))[0])
                            m.reg_write(UC_X86_REG_EIP, end)

                    u.hook_add(UC_HOOK_CODE, capture)
                    u.emu_start(0x4e2570, end, count=1000)
                    self.assertEqual(seen, [base])
                    group, model, variant = base//1000000%100, base//100%10000, base%100
                    folder = ROOT/'GundamOnline_CHINA_已解密/decrypted/item'/f'{group:02}'/f'{model:04}'
                    self.assertTrue((folder/'attr'/f'EZ_{group:02}_{model:04}_{variant:02}.vra').is_file())
                    self.assertTrue((folder/'model'/f'EM_{group:02}_{model:04}_{variant:02}.dxg').is_file())


if __name__ == '__main__':
    unittest.main()
