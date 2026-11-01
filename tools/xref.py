"""在解包镜像里找所有 call/jmp 到指定 VA 的位置（E8/E9 rel32）。

用法：
  python tools/xref.py 0xc03dc0          # 谁调用了这个函数
  python tools/xref.py 0xc03dc0 --jmp    # 连 jmp 一起找
"""
import argparse
import glob
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DUMP = os.path.join(ROOT, 'server', 'img_dump')


def regions():
    out = []
    for f in glob.glob(os.path.join(DUMP, '*')):
        if os.path.isdir(f):
            continue
        b = os.path.basename(f)
        if b.startswith('anon_'):
            base = int(b.split('_')[1], 16)
        elif b.startswith('main_'):
            base = 0x400000
        else:
            continue
        out.append((base, open(f, 'rb').read(), b))
    out.sort()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('va', type=lambda s: int(s, 0))
    ap.add_argument('--jmp', action='store_true')
    ap.add_argument('--data', action='store_true', help='同时找 4 字节立即数引用（vtable/表）')
    a = ap.parse_args()
    hits = []
    for base, data, name in regions():
        for i in range(len(data) - 5):
            if data[i] in (0xE8, 0xE9) and (data[i] == 0xE8 or a.jmp):
                rel = int.from_bytes(data[i + 1:i + 5], 'little', signed=True)
                if (base + i + 5 + rel) & 0xFFFFFFFF == a.va:
                    hits.append((base + i, name, 'call' if data[i] == 0xE8 else 'jmp'))
    for va, name, kind in hits:
        print('  %s %#x  [%s]' % (kind, va, name))
    if not hits:
        print('  (没有直接 call/jmp)')
    if a.data:
        pat = a.va.to_bytes(4, 'little')
        for base, data, name in regions():
            i = 0
            while True:
                i = data.find(pat, i)
                if i < 0:
                    break
                print('  data ref %#x  [%s]' % (base + i, name))
                i += 1


if __name__ == '__main__':
    main()
