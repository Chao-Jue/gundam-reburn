"""One-field temporary validation of the GM model camera-distance override.

No native function calls or camera-mode switches. Restart restores downloaded
tables; the durable fix is hangar_experiment's model column 15.
"""
import argparse
import json
from pathlib import Path
import frida
from probe_pilot_state import find_pid

JS = r"""
rpc.exports = {run(focusHeight, visibleOwner) {
  const registry=ptr(0x1162000).readPointer(), head=registry.add(4).readPointer();
  let node=head.add(4).readPointer(), actor=null;
  for(let i=0;i<128 && !node.isNull() && !node.equals(head);i++) {
    if(node.add(0x15).readU8()) break;
    const key=node.add(12).readU32();
    if(key===1) { actor=node.add(16).readPointer().readPointer(); break; }
    node=node.add(key>1?0:8).readPointer();
  }
  if(!actor || actor.isNull() || actor.add(8).readU32()!==777001 || actor.add(12).readU32()!==3)
    throw Error('Expected the live owned GM entity');
  const model=actor.add(0x10).readPointer();
  if(model.isNull() || model.readU32()!==101010101) throw Error('Unexpected model parameter row');
  const field=model.add(visibleOwner ? 0x32 : focusHeight ? 4 : 0x34);
  const before=visibleOwner ? field.readU8() : field.readFloat();
  if(before!==(visibleOwner ? 0 : 1)) throw Error('Unexpected current model parameter '+before);
  if(visibleOwner) field.writeU8(1); else field.writeFloat(focusHeight ? 160 : 0);
  return {pid:Process.id,actor:actor.toString(),model:model.toString(),before,
          after:visibleOwner ? field.readU8() : field.readFloat(),
          operation:visibleOwner ? 'temporary GM column14=1; native visibility eligibility' : focusHeight ? 'temporary GM focus height=160; native fallback' : 'temporary model column15=0; native default camera distance'};
}};
"""

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--focus-height', action='store_true')
    parser.add_argument('--visible-owner', action='store_true')
    args = parser.parse_args()
    session = None
    try:
        session = frida.attach(find_pid('GundamOnline_CHINA.exe'))
        script = session.create_script(JS)
        script.load()
        result = script.exports_sync.run(args.focus_height, args.visible_owner)
        Path(args.output).write_text(json.dumps(result, indent=2), encoding='utf8')
    except Exception as exc:
        Path(args.output).write_text(json.dumps({'error': str(exc)}, indent=2), encoding='utf8')
        raise
    finally:
        if session is not None:
            session.detach()
