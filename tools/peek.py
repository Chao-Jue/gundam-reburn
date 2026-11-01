#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""在**运行中**的客户端里按 RVA 读字节并反汇编（壳内的真实代码，静态文件里是密文）。

用法：
    python tools/peek.py --rva 0x7d5091 --n 96
    python tools/peek.py --rva 0x7d5091,0x7efa0a,0x7ff3da --n 64
    python tools/peek.py --pid 1234 --rva 0xc00bd0 --n 128 --no-dis

为什么需要它：GundamOnline_CHINA.exe 外层 Themida + 内层 VMProtect，
文件里 .text 的 RawSize 为 0，`tools/disasm_region.py` 只能啃明文段。
运行时这些地址已被解密成可执行代码，只有读活内存才看得到。
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time

import frida

MOD = 'GundamOnline_CHINA.exe'

JS = r'''
const reqs = %s;
const mod = Process.getModuleByName('GundamOnline_CHINA.exe');
const out = { base: mod.base.toString(), items: [] };
for (const off of reqs) {
  try {
    const p = mod.base.add(off - 0x400000);
    const b = new Uint8Array(p.readByteArray(%d));
    out.items.push({ off: off, va: p.toString(),
                     hex: Array.from(b).map(function (x) { return x.toString(16).padStart(2, '0'); }).join('') });
  } catch (e) {
    out.items.push({ off: off, err: String(e) });
  }
}
send(out);
'''


def find_pid() -> int | None:
    """tasklist 在本机对这个进程返回空，必须走 PowerShell。"""
    try:
        p = subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             "(Get-Process | Where-Object { $_.ProcessName -like '*Gundam*' } | "
             "Select-Object -First 1).Id"],
            capture_output=True)
        txt = p.stdout.decode('utf-8', 'replace').strip()
        if txt.isdigit():
            return int(txt)
    except Exception:
        pass
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--rva', required=True, help='逗号分隔的 RVA，如 0x7d5091,0x7efa0a')
    ap.add_argument('--n', type=int, default=64)
    ap.add_argument('--pid', type=int, default=None)
    ap.add_argument('--no-dis', action='store_true', help='只打印 hex，不反汇编')
    a = ap.parse_args()

    offs = [int(x.strip(), 0) for x in a.rva.split(',') if x.strip()]
    pid = a.pid or find_pid()
    if not pid:
        print('[X] 找不到客户端进程', file=sys.stderr)
        return 2

    sess = frida.attach(pid)
    sc = sess.create_script(JS % (json.dumps(offs), a.n))
    box: list = []
    sc.on('message', lambda m, d: box.append(m))
    sc.load()
    for _ in range(30):
        if box:
            break
        time.sleep(0.1)
    sess.detach()

    if not box:
        print('[X] 没拿到数据', file=sys.stderr)
        return 3
    payload = box[0].get('payload') or {}
    print('base=%s' % payload.get('base'))

    if a.no_dis:
        for it in payload.get('items', []):
            print('RVA %-10s %s' % (it.get('off'), it.get('hex') or it.get('err')))
        return 0

    try:
        import capstone
    except ImportError:
        capstone = None

    for it in payload.get('items', []):
        print('=' * 78)
        if it.get('err'):
            print('RVA %s  读取失败: %s' % (it.get('off'), it['err']))
            continue
        data = bytes.fromhex(it['hex'])
        print('RVA %s  VA %s  (%d 字节)' % (it.get('off'), it.get('va'), len(data)))
        if not capstone:
            print(data.hex(' '))
            continue
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        rva = it['off']
        for ins in md.disasm(data, rva):
            print('  %08x  %-24s %s %s' % (ins.address, ins.bytes.hex(),
                                           ins.mnemonic, ins.op_str))
    return 0


if __name__ == '__main__':
    sys.exit(main())
