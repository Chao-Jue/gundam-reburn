"""One-shot guarded experiment for base letter/permission initialization."""
import argparse
import json
from pathlib import Path
import frida
from probe_pilot_state import find_pid

JS = r"""
rpc.exports = {run() {
  const map=ptr(0x1161f90).readPointer().add(0x394).readPointer();
  if(map.isNull()) throw Error('No map');
  const first=ptr(0x116c24c).readPointer(), last=ptr(0x116c250).readPointer();
  if(last.sub(first).toInt32()!==368) throw Error('Expected four posts');
  const actors=new Map(), markers=[], end=map.add(0x1ac).readPointer();
  for(let p=map.add(0x1a8).readPointer();p.compare(end)<0;p=p.add(4)) {
    const m=p.readPointer(); if(m.add(0x104).readU32()!==22) continue;
    const ref=m.add(0x114).readPointer(), actor=ref.readPointer();
    const id=actor.add(4).readU32(), component=actor.add(0x35c).readPointer();
    if(component.isNull() || actors.has(id)) throw Error('Missing component or duplicate binding');
    actors.set(id,{m,ref,actor,component}); markers.push(m);
  }
  if(actors.size!==4) throw Error('Expected four distinct base actors');
  const plan=[];
  for(let i=0;i<4;i++) {
    const post=first.add(i*92), id=post.add(0x38).readU32(), a=actors.get(id);
    if(!a || a.actor.add(0xd8).readPointer().readU32()!==777201)
      throw Error('Unexpected base definition');
    const label=post.add(0x44).readU32();
    if(label>2) throw Error('Unexpected letter');
    plan.push({...a,id,label,beforeLetter:a.actor.add(0xc8).readU8(),
               beforeFlags:a.component.add(0xd2).readU8()});
  }
  const team=ptr(0x1161f28).readPointer().add(0x3a9cc).readU32();
  const bind=new NativeFunction(ptr(0x87d650),'void',['pointer','pointer'],'thiscall');
  const enable=new NativeFunction(ptr(0x874fd0),'void',['pointer','uint'],'thiscall');
  const update=new NativeFunction(ptr(0x87d4e0),'void',['pointer','float','float'],'thiscall');
  for(const a of plan) {
    a.actor.add(0xc8).writeU8(a.label);
    a.component.add(0xd2).writeU8(a.beforeFlags|1);
    a.ref.add(8).writeU32(a.ref.add(8).readU32()+1);
    bind(a.m,a.ref);
    enable(a.m,a.actor.add(0xf4).readU32()===team?1:0);
    update(a.m,0,0.016);
  }
  const game=ptr(0x1161f28).readPointer();
  const ui=ptr(0x1161f78).readPointer();
  const previousSelectionTime=ui.add(0x100).readFloat();
  // Debug only: allow a human to exercise selection after lengthy live inspection.
  if(game.add(0x25098).readU8()===1 && previousSelectionTime===0)
    ui.add(0x100).writeFloat(120);
  const gate=(address,obj,...args)=>new NativeFunction(ptr(address),'uint',
    ['pointer',...args.map(()=> 'uint')],'thiscall')(obj,...args)&255;
  return {operation:'temporary base label/permission initialization; restart restores original state',
          gates:{canChoose:gate(0x440770,game,1),selectedMechReady:gate(0x43f600,game,1),
                 previousSelectionTime,currentSelectionTime:ui.add(0x100).readFloat(),
                 modalBlocked:gate(0x5e8a30,ptr(0x1161f74).readPointer()),
                 baseEligible:plan.map(a=>gate(0x877760,a.m))},
          changes:plan.map(a=>({id:a.id,beforeLetter:a.beforeLetter,afterLetter:a.label,
                               beforeFlags:a.beforeFlags,afterFlags:a.component.add(0xd2).readU8()}))};
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
        try:
            result = script.exports_sync.run()
        except Exception as exc:
            result = {'error': str(exc)}
        Path(args.output).write_text(json.dumps(result, indent=2), encoding='utf8')
    finally:
        session.detach()
