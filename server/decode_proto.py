"""离线解码客户端收发帧（Camellia-128-ECB）。

用法：
  python server/decode_proto.py --keymat 1111...2222... [--log server/probe_light.log]

已知结论（2026-10-17 第十七轮验证）：
  · 会话密钥 = 服务端下发的 32 字节材料，**拆成两半各 16 字节**；
  · 客户端上行（client→server）用 **后半** [16:32]；
  · 服务端下行（server→client）用 **前半** [0:16]；
  · 算法 Camellia-128-ECB，无 IV、无填充（整块，不足补 0）；
  · 帧格式：u32 LE 密文长度 + 密文。
"""
import argparse
import json
import subprocess
import sys


def camellia(key, data, decrypt=False):
    cmd = ['openssl', 'enc']
    if decrypt:
        cmd.append('-d')
    cmd += ['-camellia-128-ecb', '-K', key.hex(), '-nopad']
    p = subprocess.run(cmd, input=data, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode('utf-8', 'replace')[:120])
    return p.stdout


def visual(b):
    return ''.join(chr(c) if 32 <= c < 127 else '.' for c in b)


def dump(tag, data, key):
    """data = u32 LE len + cipher"""
    i, n = 0, len(data)
    while i + 4 <= n:
        flen = int.from_bytes(data[i:i + 4], 'little')
        if flen <= 0 or flen > 65535 or i + 4 + flen > n:
            print(f'  {tag} 剩余 {data[i:].hex()}')
            return
        ct = data[i + 4:i + 4 + flen]
        pt = camellia(key, ct, decrypt=True) if flen % 16 == 0 else b''
        print(f'  {tag} frame len={flen}')
        print(f'     ct {ct.hex()}')
        print(f'     pt {pt.hex()}  |{visual(pt)}|')
        i += 4 + flen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--keymat', required=True, help='32 字节密钥材料 hex')
    ap.add_argument('--log', default='server/probe_light.log')
    args = ap.parse_args()

    km = bytes.fromhex(args.keymat)
    if len(km) != 32:
        print('keymat 必须是 32 字节')
        return 1
    up, down = km[16:32], km[0:16]
    print(f'上行密钥(client->server) = {up.hex()}')
    print(f'下行密钥(server->client) = {down.hex()}')
    print()

    for line in open(args.log, encoding='utf-8', errors='replace'):
        if '"ev": "SEND"' not in line and '"ev": "RECV"' not in line:
            continue
        ts = line[:8]
        try:
            o = json.loads(line.split(' ', 1)[1])
        except Exception:
            continue
        h = o.get('hex') or ''
        if not h:
            continue
        data = bytes.fromhex(h)
        key = up if o['ev'] == 'SEND' else down
        print(f'{ts} {o["ev"]} {len(data)} 字节')
        dump('', data, key)
    return 0


if __name__ == '__main__':
    sys.exit(main())
