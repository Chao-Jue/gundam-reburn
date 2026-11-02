"""Explicit one-shot live experiment for existing base actors; not a persistent patch."""
import argparse
import json
from pathlib import Path
import frida
from probe_pilot_state import find_pid

JS = r"""
rpc.exports = { run() {
  const world=ptr(0x1161f90).readPointer(), map=world.add(0x394).readPointer();
  const first=ptr(0x116c24c).readPointer(), end=ptr(0x116c250).readPointer();
  if (end.sub(first).toInt32()!==4*92 || map.isNull()) throw Error('Expected four-base scene');
  function kinds() {
    const out=[], end=map.add(0x1ac).readPointer();
    for(let p=map.add(0x1a8).readPointer(); p.compare(end)<0; p=p.add(4))
      out.push(p.readPointer().add(0x104).readU32());
    return out;
  }
  const before=kinds(), changes=[];
  if(before.filter(k=>k===22).length===4) {
    const update=new NativeFunction(ptr(0x87d4e0),'void',['pointer','float','float'],'thiscall');
    const color=new NativeFunction(ptr(0x876820),'void',['pointer','uint'],'thiscall');
    const end=map.add(0x1ac).readPointer();
    for(let p=map.add(0x1a8).readPointer();p.compare(end)<0;p=p.add(4)) {
      const marker=p.readPointer();
      if(marker.add(0x104).readU32()===22) {
        update(marker,0,0.016);
        color(marker,1);
      }
    }
    return {before,after:kinds(),operation:'refresh existing marker state/color only'};
  }
  const registry=ptr(0x1162000).readPointer(), head=registry.add(4).readPointer();
  const attach=new NativeFunction(ptr(0x454570),'void',['pointer','pointer','uint'],'thiscall');
  for(let i=0;i<4;i++) {
    const id=first.add(i*92+0x38).readU32(); let node=head.add(4).readPointer(), ref=null;
    for(let n=0;n<64 && !node.equals(head) && node.add(0x15).readU8()===0;n++) {
      const key=node.add(12).readU32();
      if(key===id) {ref=node.add(16).readPointer();break;}
      node=node.add(id<key?0:8).readPointer();
    }
    if(ref===null || ref.readPointer().isNull()) throw Error('Base actor missing');
    const actor=ref.readPointer(), definition=actor.add(0xd8).readPointer();
    if(definition.isNull() || definition.readU32()!==777201) throw Error('Unexpected actor definition');
    const field=definition.add(0x150), previous=field.readU32();
    if(previous!==0 && previous!==22) throw Error('Unexpected minimap category');
    field.writeU32(22);
    ref.add(8).writeU32(ref.add(8).readU32()+1); // pass CCharaRef by value; native callee releases it
    attach(world,ref,0);
    changes.push({id,previous,current:field.readU32()});
  }
  return {before,after:kinds(),changes};
} };
"""

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    pid = find_pid('GundamOnline_CHINA.exe')
    if not pid:
        raise SystemExit('Client not running')
    session = frida.attach(pid)
    try:
        script = session.create_script(JS)
        script.load()
        try:
            result = script.exports_sync.run()
        except Exception as exc:
            result = {'error': str(exc)}
        Path(args.output).write_text(json.dumps(result, indent=2), encoding='utf-8')
    finally:
        session.detach()
