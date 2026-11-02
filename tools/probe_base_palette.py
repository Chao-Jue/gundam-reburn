"""Read-only live base marker palette and enable-state snapshot."""
import json
from pathlib import Path
from probe_pilot_state import Reader, find_pid


def snapshot(r):
    game = r.u32(0x1161F28)
    world = r.u32(0x1161F90)
    settings = r.u32(0x1161F68)
    palette = r.u32(r.u32(0x1161F80) + 0x18)
    result = {'game': game, 'team_3a9cc': r.u32(game + 0x3a9cc),
              'selection_gates': {hex(o): r.u32(game + o) for o in (0x109f8, 0x10a04, 0x10a08, 0x10a18, 0x1067c)},
              'ui_timers_raw': {hex(o): r.read(r.u32(0x1161F78) + o, 4).hex() for o in (0x100, 0x104)},
              'team_311dc': r.u32(game + 0x311dc),
              'palette_overrides': [r.u32(settings + o) for o in (0x3c, 0x40)],
              'palette_defaults': {hex(o): hex(r.u32(palette + o)) for o in (0x38, 0x68, 0x6c, 0x70, 0x8c, 0x90)},
              'markers': []}
    ctrl = r.u32(world + 0x394)
    for p in range(r.u32(ctrl + 0x1a8), r.u32(ctrl + 0x1ac), 4):
        m = r.u32(p)
        if r.u32(m + 0x104) != 22:
            continue
        actor = r.u32(r.u32(m + 0x114))
        component = r.u32(actor + 0x35c)
        result['markers'].append({'address': m, 'raw': r.read(m, 0x190).hex(),
                                  'vtable': r.u32(m),
                                  'entity_id': r.u32(actor + 4),
                                  'letter_index': r.u8(actor + 0xc8),
                                  'team': r.u32(actor + 0xf4),
                                  'component': component,
                                  'spawn_enabled': r.u8(component + 0xd2) if component else None,
                                  'hp_widget': r.read(r.u32(m + 0x138), 0x54).hex()})
    return result


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    r = Reader(find_pid('GundamOnline_CHINA.exe'))
    try:
        Path(args.output).write_text(json.dumps(snapshot(r), indent=2), encoding='utf8')
    finally:
        r.close()
