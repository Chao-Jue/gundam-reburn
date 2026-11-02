"""One-shot native TPS camera switch to diagnose a stranded event camera."""
import argparse
import json
from pathlib import Path
import frida
from probe_pilot_state import find_pid

JS = r"""
rpc.exports = {run() {
  const camera=ptr(0x1161ff4).readPointer(), before=camera.add(0x54).readU32();
  if(before!==2 || ptr(0x116a3dc).readU8()!==0) throw Error('Not an inactive stranded event camera');
  const switchView=new NativeFunction(ptr(0xa19f30),'void',['pointer','uint','uint','uint'],'thiscall');
  switchView(camera,3,0,0);
  return {before,after:camera.add(0x54).readU32(),operation:'temporary switch from inactive event view to native TPS'};
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
