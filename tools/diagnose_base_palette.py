"""One-shot palette experiment; explicit test colors, not recovered game data."""
import argparse
import json
from pathlib import Path
import frida
from probe_pilot_state import find_pid

JS = r"""
rpc.exports = {run() {
  const world=ptr(0x1161f90).readPointer(), map=world.add(0x394).readPointer();
  if(map.isNull()) throw Error('No map');
  const markers=[], end=map.add(0x1ac).readPointer();
  for(let p=map.add(0x1a8).readPointer();p.compare(end)<0;p=p.add(4)) {
    const m=p.readPointer(); if(m.add(0x104).readU32()===22) markers.push(m);
  }
  if(markers.length!==4) throw Error('Expected four existing base markers');
  const palette=ptr(0x1161f80).readPointer().add(0x18).readPointer();
  const before=[palette.add(0x90).readU32(),palette.add(0x8c).readU32()];
  if(before.some(v=>v!==0)) throw Error('Nonzero palette; preserve user colors');
  // Deliberately chosen blue/red for diagnosis only; not original resource values.
  palette.add(0x90).writeU32(0xff33aaff); palette.add(0x8c).writeU32(0xffff4444);
  const color=new NativeFunction(ptr(0x876820),'void',['pointer','uint'],'thiscall');
  markers.forEach(m=>color(m,1));
  return {before,after:[palette.add(0x90).readU32(),palette.add(0x8c).readU32()],
          operation:'temporary diagnostic team palette; restart restores original values'};
}};
"""

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    session = frida.attach(find_pid('GundamOnline_CHINA.exe'))
    try:
        script = session.create_script(JS)
        script.load()
        Path(args.output).write_text(json.dumps(script.exports_sync.run(), indent=2), encoding='utf8')
    finally:
        session.detach()
