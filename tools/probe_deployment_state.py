"""Read-only snapshot of deployment posts and minimap configuration in the current client."""
import json
import struct
import argparse
from pathlib import Path
from probe_pilot_state import Reader, find_pid


def snapshot(r):
    result = {}
    begin = r.u32(0x116C24C) or 0
    end = r.u32(0x116C250) or 0
    result['post_span'] = [begin, end]
    result['posts'] = []
    if begin and 0 <= end - begin <= 92 * 50 and (end - begin) % 92 == 0:
        for address in range(begin, end, 92):
            raw = r.read(address, 92)
            if raw:
                result['posts'].append({'address': address, 'type': struct.unpack_from('<I', raw)[0],
                    'team': struct.unpack_from('<i', raw, 8)[0],
                    'label_index': struct.unpack_from('<i', raw, 68)[0],
                    'position': struct.unpack_from('<3f', raw, 72),
                    'flags': list(raw[84:92]), 'raw': raw.hex()})
    table = r.u32(0x117B654) or 0
    result['minimap_table'] = table
    if table:
        result['minimap_rows'] = r.u32(table + 12)
        header = r.u32(table + 8) or 0
        node = r.u32(header + 4) if header else 0
        seen = set()
        while node and node != header and node not in seen and len(seen) < 100:
            seen.add(node)
            data = r.read(node, 44)
            if not data or data[41]:
                break
            key = struct.unpack_from('<i', data, 12)[0]
            if key == 31:
                result['post_icon_config'] = list(struct.unpack_from('<7i', data, 12))
                break
            node = struct.unpack_from('<I', data, 0 if key > 31 else 8)[0]
    game = r.u32(0x1161F28) or 0
    if game:
        result['game_team'] = r.u32(game + 0x2508C)
        result['prestart'] = r.u8(game + 0x25098)
        task = r.u32(game + 0x10894) or 0
        result['battle_state'] = r.u32(task + 0x30) if task else None
    ui = r.u32(0x1161F78) or 0
    if ui:
        result['ui_state'] = r.u32(ui + 0x30)
        result['ui_substate'] = r.u32(ui + 0x34)
        result['maps'] = []
        world = r.u32(0x1161F90) or 0
        for owner, offset in ((ui, 0x14C), (ui, 0x150), (world, 0x394)):
            m = r.u32(owner + offset) or 0 if owner else 0
            entry = {'offset': offset, 'address': m}
            if m:
                entry['layers'] = []
                for layer_index in range(8):
                    layer = r.u32(m + 0x164 + 4 * layer_index) or 0
                    vt = r.u32(layer) or 0 if layer else 0
                    entry['layers'].append({'address': layer, 'vtable': vt,
                        'add_function': r.u32(vt + 0x18) if vt else None,
                        'raw': (r.read(layer, 256) or b'').hex() if layer else ''})
                a, b = r.u32(m + 0x1A8) or 0, r.u32(m + 0x1AC) or 0
                entry['markers_span'] = [a, b]
                entry['markers'] = []
                if a and 0 <= b-a <= 4096:
                    for ptr in range(a, b, 4):
                        obj = r.u32(ptr) or 0
                        entry['markers'].append({'address': obj, 'vtable': r.u32(obj),
                            'kind': r.u32(obj + 0x104), 'post_index': r.u32(obj + 0x170),
                            'flags': r.u32(obj + 0x8C)})
            result['maps'].append(entry)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output')
    args = parser.parse_args()
    pid = find_pid('GundamOnline_CHINA.exe')
    if not pid:
        raise SystemExit('Client is not running')
    reader = Reader(pid)
    try:
        output = json.dumps({'pid': pid, **snapshot(reader)}, indent=2)
        if args.output:
            Path(args.output).write_text(output, encoding='utf-8')
        else:
            print(output)
    finally:
        reader.close()
