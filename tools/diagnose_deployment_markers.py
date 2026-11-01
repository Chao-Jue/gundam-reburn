"""One-shot diagnostic: run the client's existing marker initialization function.

No executable bytes or protocol definitions are patched. This is a runtime
experiment, not a persistent fix. Requires an already loaded prestart map.
"""
import json
import argparse
from pathlib import Path
import frida
from probe_pilot_state import find_pid

JS = r"""
rpc.exports = {
  inspect(rebuild, homePreview) {
    const game = ptr(0x1161f28).readPointer();
    const world = ptr(0x1161f90).readPointer();
    const map = world.add(0x394).readPointer();
    function state() {
      const a = map.add(0x1a8).readPointer(), b = map.add(0x1ac).readPointer();
      const posts = (ptr(0x116c250).readPointer().toUInt32() -
                     ptr(0x116c24c).readPointer().toUInt32()) / 92;
      const kinds = [];
      for (let p = a; p.compare(b) < 0 && kinds.length < 100; p = p.add(4)) {
        const marker = p.readPointer();
        kinds.push(marker.add(0x104).readU32());
      }
      return { posts, kinds, prestart: game.add(0x25098).readU8() };
    }
    const before = state();
    if (homePreview) {
      if (!before.prestart || before.posts !== 14 || !before.kinds.includes(31))
        throw new Error('Preview requires existing deployment markers');
      const first = ptr(0x116c24c).readPointer();
      const setPost = new NativeFunction(ptr(0x8890c0), 'void', ['pointer','int'], 'thiscall');
      const a = map.add(0x1a8).readPointer(), b = map.add(0x1ac).readPointer();
      const counters = [0, 0];
      for (let i = 0; i < 14; i++) {
        const post = first.add(92 * i);
        const team = post.add(8).readU32();
        post.writeU32(0);
        post.add(68).writeU32(counters[team]++);
      }
      for (let p = a; p.compare(b) < 0; p = p.add(4)) {
        const marker = p.readPointer();
        if (marker.add(0x104).readU32() !== 31) continue;
        const index = marker.add(0x170).readS32();
        marker.add(0x170).writeS32(-1);
        setPost(marker, index);
      }
      return { before, after: state(), preview: 'type0 home-base glyphs; existing coordinates unchanged' };
    }
    if (!rebuild) return { before };
    if (before.posts !== 14 || !before.prestart || before.kinds.includes(31))
      throw new Error('Unexpected state; refusing duplicate initialization');
    const initialize = new NativeFunction(ptr(0x448570), 'void', ['pointer'], 'thiscall');
    initialize(game);
    return { before, after: state() };
  }
};
"""

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--rebuild', action='store_true')
    ap.add_argument('--home-preview', action='store_true')
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    pid = find_pid('GundamOnline_CHINA.exe')
    if not pid:
        raise SystemExit('Client is not running')
    session = frida.attach(pid)
    try:
        script = session.create_script(JS)
        script.load()
        try:
            result = script.exports_sync.inspect(args.rebuild, args.home_preview)
        except Exception as exc:
            result = {'error': str(exc)}
        Path(args.output).write_text(json.dumps(result, indent=2), encoding='utf-8')
    finally:
        session.detach()
