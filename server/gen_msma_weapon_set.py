# -*- coding: utf-8 -*-
"""按规格生成 msma/msma_weapon_set.csv。

规格来源：server/表_msma_weapon_set_规格.md（Ghidra 反编译 0x551BC0 得出）

    python server/gen_msma_weapon_set.py [--rows N] [--region CHINA|ALL]
                                        [--group MAIN|EX|SUB] [--kind MACHINEGUN|...]
                                        [--out 路径] [--dry]

默认直接写到解密包的 settings 目录，fake_auth 会自动读取：
    GundamOnline_CHINA_已解密/decrypted/settings/msma/msma_weapon_set.csv
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.normpath(os.path.join(
    HERE, '..', 'GundamOnline_CHINA_已解密', 'decrypted', 'settings',
    'msma', 'msma_weapon_set.csv'))

# 列定义：None = 不读的列，留空
#   0 主键 / 2 / 4 武器组 / 5 武器种类 / 6 bool / 7
#   8,10,11 | 12,14,15 | 16,18,19  三组
#   22 24 25 26 27 / 28 地区
NCOL = 29
UNUSED = {1, 3, 9, 13, 17, 20, 21, 23}

GROUPS = ('MAIN', 'EX', 'SUB', '0')
KINDS = ('MACHINEGUN', 'MACHINEGUN2', 'MACHINEGUN3', 'SUBMACHINEGUN', 'SHOTGUN',
         'BEAM_RIFLE', 'BEAM_SPRAYGUN', 'WRESTLE', 'CHARGE_RIFLE', 'CHARGE_BAZOOKA',
         'SNIPER_RIFLE', 'BEAM_SNIPE', 'TRENCH_MORTAR', 'REPAIR', 'SHIELD',
         'BAZOOKA', 'MISSILE', 'HOWITZER', 'LANDMINE', 'HAND_THROW', 'HAND_THROW2',
         'RADARPOD', 'REPAIRPOD', 'CAMERAGUN', 'BULLET_PACK', 'AAGPOD',
         'REPAIR_PACK', '-')
REGIONS = ('ALL', 'CHINA', 'JAPAN')


def build(rows=1, region='CHINA', group='MAIN', kind='MACHINEGUN', header=True):
    """header=True 时第一行是 # 开头的列名（加载器会跳过前 2 行）"""
    out = []
    if header:
        # 加载器跳过前 2 行，所以给 1 行列名 + 1 行空注释
        out.append('#' + ','.join('C%d' % i for i in range(NCOL)))
        out.append('#' + ','.join('-' for _ in range(NCOL)))
    for r in range(1, max(0, rows) + 1):
        row = ['0'] * NCOL
        for c in UNUSED:
            row[c] = ''
        row[0] = str(r)          # 主键
        row[2] = '0'
        row[4] = group
        row[5] = kind
        row[6] = '0'
        row[7] = '0'
        for base in (8, 12, 16):          # 三组 × 3
            row[base] = '0'
            row[base + 2] = '0'
            row[base + 3] = '0'
        for c in (22, 24, 25, 26, 27):
            row[c] = '0'
        row[28] = region
        out.append(','.join(row))
    return ('\r\n'.join(out) + '\r\n').encode('utf-8')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rows', type=int, default=1)
    ap.add_argument('--region', default='CHINA', choices=REGIONS)
    ap.add_argument('--group', default='MAIN', choices=GROUPS)
    ap.add_argument('--kind', default='MACHINEGUN', choices=KINDS)
    ap.add_argument('--out', default=DEFAULT_OUT)
    ap.add_argument('--dry', action='store_true', help='只打印，不写文件')
    a = ap.parse_args()

    blob = build(a.rows, a.region, a.group, a.kind)
    lines = blob.decode('utf-8').splitlines()
    print('生成 %d 字节，%d 行（含 2 行表头），%d 列'
          % (len(blob), len([l for l in lines if l]), len(lines[0].split(','))))
    for l in lines[:4]:
        print('   ', l[:150])
    if a.dry:
        return 0
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, 'wb') as f:
        f.write(blob)
    print('已写入', a.out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
