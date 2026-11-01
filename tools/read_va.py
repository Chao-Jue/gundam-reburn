"""从**正在运行**的进程里读内存，验证 dump 是否与当前进程一致。

用法：
  python tools/read_va.py --va 0x7fd2e0 --n 64
  python tools/read_va.py --va 0x7fcf90 --n 64 --dis      # 顺便反汇编
  python tools/read_va.py --dump 0x7f0000 0x810000 --out server/live_code.bin
"""
import argparse
import os
import subprocess
import sys

import frida

JS = r'''
const reqs = JSON.parse(%s);
const out = {};
for (const k of Object.keys(reqs)) {
  const r = reqs[k];
  try {
    out[k] = Array.from(new Uint8Array(ptr(r[0]).readByteArray(r[1])))
      .map(x => x.toString(16).padStart(2, '0')).join('');
  } catch (e) { out[k] = 'ERR:' + String(e); }
}
send(out);
'''


def find_pid():
    out = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq GundamOnline_CHINA.exe', '/FO', 'CSV', '/NH'],
                         capture_output=True)
    txt = out.stdout.decode('mbcs', 'replace')
    for line in txt.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=int)
    ap.add_argument('--va', type=lambda s: int(s, 0))
    ap.add_argument('--n', type=int, default=64)
    ap.add_argument('--dis', action='store_true')
    ap.add_argument('--dump', nargs=2, type=lambda s: int(s, 0), metavar=('START', 'END'))
    ap.add_argument('--out', default='server/live_region.bin')
    a = ap.parse_args()
    pid = a.pid or find_pid()
    if not pid:
        print('客户端没在跑')
        return 1
    session = frida.attach(pid)
    got = {}

    def on_msg(msg, data):
        if msg.get('type') == 'payload':
            got.update(msg['payload'])
        else:
            print('[msg]', msg)

    if a.dump:
        s, e = a.dump
        reqs = {'r': [s, e - s]}
    else:
        reqs = {'r': [a.va, a.n]}
    script = session.create_script(JS % __import__('json').dumps(__import__('json').dumps(reqs)))
    script.on('message', on_msg)
    script.load()
    for _ in range(100):
        if got:
            break
        __import__('time').sleep(0.05)
    session.detach()

    raw = got.get('r', '')
    if raw.startswith('ERR'):
        print(raw)
        return 1
    data = bytes.fromhex(raw)
    if a.dump:
        os.makedirs(os.path.dirname(a.out), exist_ok=True)
        open(a.out, 'wb').write(data)
        print('wrote %s (%d bytes) from %#x' % (a.out, len(data), a.dump[0]))
        return 0
    print('VA %#x (%d bytes):' % (a.va, len(data)))
    for i in range(0, len(data), 16):
        print('  %08x  %s' % (a.va + i, data[i:i + 16].hex(' ')))
    if a.dis:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        print('--- disasm ---')
        for ins in md.disasm(data, a.va):
            print('  %08x  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str))
    return 0


if __name__ == '__main__':
    sys.exit(main())
