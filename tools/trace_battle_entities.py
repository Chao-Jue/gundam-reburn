"""Bounded live entity callback/exception trace; no gameplay state mutations."""
import argparse
import json
import time
from pathlib import Path
import frida
from probe_pilot_state import find_pid

JS = r"""
const safely=f=>{try{return f();}catch(e){return String(e);}};
for(const address of [0xaf47c0,0xa554d0,0x4ab220,0x4546c0,0x490f30]) {
  let count=0;
  Interceptor.attach(ptr(address),{onEnter(args) {
    if(count++>20)return;
    send({event:'enter',address:address.toString(16),this:this.context.ecx.toString(),
      args:Array.from({length:8},(_,i)=>args[i].toString()),
      world:safely(()=>ptr(0x1161f90).readPointer().toString()),
      map:safely(()=>ptr(0x1161f90).readPointer().add(0x394).readPointer().toString())});
  }});
}
Process.setExceptionHandler(details=>{
  send({event:'exception',type:details.type,address:details.address.toString(),
    memory:details.memory,registers:details.context,
    backtrace:Thread.backtrace(details.context,Backtracer.FUZZY).map(a=>a.toString())});
  return false;
});
send({event:'trace_ready'});
"""

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', required=True)
    ap.add_argument('--seconds', type=int, default=120)
    args = ap.parse_args()
    with Path(args.output).open('w', encoding='utf8') as out:
        deadline = time.monotonic() + args.seconds
        def log(message, data=None):
            out.write(json.dumps(message, ensure_ascii=False) + '\n')
            out.flush()
        while time.monotonic() < deadline:
            pid = find_pid('GundamOnline_CHINA.exe')
            if not pid:
                time.sleep(.25)
                continue
            try:
                session = frida.attach(pid)
            except frida.ProcessNotFoundError:
                continue
            log({'event': 'attached', 'pid': pid})
            script = session.create_script(JS)
            script.on('message', log)
            script.load()
            while not session.is_detached and time.monotonic() < deadline:
                time.sleep(.25)
            log({'event': 'detached', 'pid': pid})
            try:
                session.detach()
            except frida.InvalidOperationError:
                pass
