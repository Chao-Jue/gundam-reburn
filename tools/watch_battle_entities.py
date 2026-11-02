"""Read-only bounded capture across launcher restarts and deployment transitions."""
import argparse
import json
import time
from pathlib import Path
from probe_pilot_state import Reader, find_pid
from probe_battle_entities import snapshot


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', required=True)
    ap.add_argument('--seconds', type=int, default=1800)
    args = ap.parse_args()
    deadline = time.monotonic() + args.seconds
    reader = None
    last_pid = None
    last_state = None
    with Path(args.output).open('w', encoding='utf8') as out:
        def emit(value):
            out.write(json.dumps(value, ensure_ascii=False) + '\n')
            out.flush()
        emit({'event': 'watching'})
        try:
            while time.monotonic() < deadline:
                try:
                    pid = find_pid('GundamOnline_CHINA.exe')
                    if pid != last_pid:
                        if reader:
                            reader.close()
                        reader = Reader(pid) if pid else None
                        last_pid = pid
                        last_state = None
                        emit({'event': 'pid', 'pid': pid})
                    if reader:
                        value = snapshot(reader)
                        state = [(e['entity'], e.get('actor'), e.get('fields')) for e in value['entities']]
                        if state != last_state:
                            emit({'event': 'state', 'pid': pid, 'snapshot': value})
                            last_state = state
                except Exception as exc:
                    emit({'event': 'error', 'message': str(exc)})
                    if reader:
                        reader.close()
                    reader = None
                    last_pid = None
                    time.sleep(1)
                time.sleep(.25)
        finally:
            if reader:
                reader.close()
