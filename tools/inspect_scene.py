"""One-shot read-only scene/task inspection of the running client."""
import argparse
import json
from pathlib import Path

from probe_pilot_state import Reader, find_pid, snapshot


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--va', type=lambda v: int(v, 0))
    parser.add_argument('--size', type=lambda v: int(v, 0), default=0x80)
    parser.add_argument('--out')
    args = parser.parse_args()
    reader = Reader(find_pid('GundamOnline_CHINA.exe'))
    try:
        state = snapshot(reader)
        game = state.get('game') or 0
        proto = state.get('proto') or 0
        state['mission_ready'] = reader.u8(game + 0x312B0) if game else None
        state['coop_gate'] = reader.u8(proto + 0x29E + 0x59) if proto else None
        result = {'state': state, 'memory': {}}

        def dump(name, address, size=0x80):
            if address:
                result['memory'][name] = {
                    'address': hex(address),
                    'words': [hex(reader.u32(address + i) or 0) for i in range(0, size, 4)]}

        if args.va:
            dump('requested', args.va, args.size)
        else:
            scene = state.get('scene') or 0
            dump('scene', scene)
            if scene:
                ref = reader.u32(scene + 8) or 0
                dump('scene_task_ref', ref)
                task = reader.u32(ref) if ref else 0
                dump('scene_task', task)
            dump('ui_manager', reader.u32(0x1161F2C), 0x220)
        output = json.dumps(result, ensure_ascii=True, indent=2)
        if args.out:
            Path(args.out).write_text(output, encoding='utf-8')
        else:
            print(output)
    finally:
        reader.close()


if __name__ == '__main__':
    main()
