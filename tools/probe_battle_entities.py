"""Read-only entity registry snapshot, including the player and network bases."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from probe_pilot_state import Reader, find_pid
from probe_battle_weapons import weapon_state, weapon_visuals


def render_state(r, actor):
    # 490F30 loads a model resource into actor+124. CSelfCharaController
    # vtable+2C -> 673D20 returns controller+14, a CMoveControl, NOT the model.
    # Keep both identities separate; neither controller proves model visibility.
    controller = r.u32(actor + 0x280)
    movement = r.u32(controller + 0x14) if controller else None
    render_object = r.u32(actor + 0x124)
    raw = r.read(render_object, 0x400) if render_object else None
    parameters = r.u32(actor + 0x10)
    parameter_raw = r.read(parameters, 0x1a0) if parameters else None
    root = r.u32(render_object + 0x2c) if render_object else None
    root_raw = r.read(root, 0x200) if root else None
    return {'controller': controller, 'movement': movement, 'render_object': render_object,
            'render_raw': raw.hex() if raw is not None else None,
            'model_parameters': parameters,
            'model_parameters_raw': parameter_raw.hex() if parameter_raw is not None else None,
            'model_root': root, 'model_root_raw': root_raw.hex() if root_raw is not None else None}


def snapshot(r):
    registry = r.u32(0x1162000)
    head = r.u32(registry + 4)
    result = []
    for entity in (1, 100, 101, 102, 103):
        node = r.u32(head + 4)
        seen = set()
        entry = {'entity': entity, 'actor': None}
        while node and node != head and node not in seen and len(seen) < 128:
            seen.add(node)
            if r.u8(node + 0x15):
                break
            key = r.u32(node + 12)
            if key == entity:
                actor = r.u32(r.u32(node + 16))
                entry['actor'] = actor
                if actor:
                    entry['fields'] = {hex(o): r.u32(actor + o) for o in
                                       (4, 8, 0xc, 0xd8, 0xdc, 0xe0, 0xf4, 0x10c, 0x280, 0x35c)}
                    model = r.u32(actor + 0x280)
                    entry['actor_raw'] = r.read(actor, 0x400).hex()
                    entry['model_raw'] = r.read(model, 0x180).hex() if model else None
                    entry['render_state'] = render_state(r, actor)
                    entry['weapon_state'] = weapon_state(r, actor)
                    entry['weapon_visuals'] = weapon_visuals(r, actor)
                break
            node = r.u32(node + (0 if entity < key else 8))
        result.append(entry)
    world = r.u32(0x1161f90)
    game = r.u32(0x1161f28)
    camera = r.u32(0x1161ff4)
    camera_info = None
    if camera:
        mode = r.u32(camera + 0x54)
        view = r.u32(camera + 0x14 + mode * 4) if mode is not None and mode < 16 else 0
        if view:
            vt = r.u32(view)
            col = r.u32(vt - 4)
            descriptor = r.u32(col + 12)
            camera_info = {'mode': mode, 'view': view, 'vtable': vt,
                           'class': r.read(descriptor + 8, 100).split(b'\0')[0].decode('ascii', 'replace'),
                           'raw': r.read(view, 0x300).hex()}
            camera_info['event_active'] = r.u8(0x116a3dc)
            camera_info['event_previous_mode'] = r.u32(0xf32568)
            eye = r.u32(camera + 4)
            eye_raw = r.read(eye, 0x300) if eye else None
            camera_info['scene_camera'] = eye
            camera_info['scene_camera_raw'] = eye_raw.hex() if eye_raw is not None else None
            camera_info['views'] = []
            for index in range(12):
                candidate = r.u32(camera + 0x14 + index * 4)
                if not candidate:
                    continue
                try:
                    candidate_vt = r.u32(candidate)
                    candidate_col = r.u32(candidate_vt - 4)
                    desc = r.u32(candidate_col + 12)
                    name = r.read(desc + 8, 100).split(b'\0')[0].decode('ascii', 'replace')
                    camera_info['views'].append([index, name])
                except Exception:
                    pass
    return {'pid': getattr(r, 'pid', None), 'captured_at': datetime.now(timezone.utc).isoformat(),
            'entities': result, 'world_raw': r.read(world, 0x400).hex(),
            'camera': camera_info,
            'player_game_raw': r.read(game + 0x3a9a0, 0x40).hex()}


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    r = Reader(find_pid('GundamOnline_CHINA.exe'))
    try:
        Path(args.output).write_text(json.dumps(snapshot(r), indent=2), encoding='utf8')
    finally:
        r.close()
