#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""从镜像里解出**客户端自己的**表清单，并与解包 CSV 做差异对照。

清单的静态位置（已核对反汇编 0x544620）：
    0xcb9490 起，每项 8 字节 {u32 序号, wchar_t* 名字}
    走到「名字指针 == 0」为止，共 70 项
    0x544620 = 名字 -> 序号，查不到返回 0x47(71)
"""
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

import pefile

ROOT = Path(__file__).resolve().parent.parent
IMG = ROOT / 'server' / 'img_dump' / 'main_GundamOnline_CHINA.exe'
CSV = ROOT / 'GundamOnline_CHINA_已解密' / 'decrypted' / 'settings' / 'download_list.csv'
LOG = ROOT / 'server' / 'fake_auth.log'
OUT = ROOT / 'server' / '客户端表清单.md'
BASE = 0x400000
TABLE = 0xCB9490


def main() -> int:
    img = IMG.read_bytes()

    def u32(va: int) -> int:
        return struct.unpack_from('<I', img, va - BASE)[0]

    def wstr(va: int, limit: int = 300) -> str:
        out = []
        for i in range(limit):
            c = struct.unpack_from('<H', img, va - BASE + i * 2)[0]
            if c == 0:
                break
            out.append(chr(c))
        return ''.join(out)

    client = []
    for i in range(300):
        idx = u32(TABLE + i * 8)
        p = u32(TABLE + i * 8 + 4)
        if p == 0:
            break
        client.append((i, idx, wstr(p)))

    n2p = {}
    for r in CSV.read_text(encoding='utf-8-sig').splitlines():
        if not r.strip() or r.startswith('#'):
            continue
        c = r.split(',')
        if len(c) >= 2:
            n2p[c[0]] = c[1]

    rounds, cur = [], []
    for line in LOG.read_text(encoding='utf-8', errors='replace').splitlines():
        m = re.search(r'收到 0xF86A (\S+?)，回', line)
        if m:
            if '本轮第 1 张' in line and cur:
                rounds.append(cur)
                cur = []
            cur.append(m.group(1))
    if cur:
        rounds.append(cur)
    req = set(rounds[-1]) if rounds else set()

    L = []
    L.append('# 客户端自己的表清单（权威版）\n\n')
    L.append('> 来源：exe 静态数组 `0xcb9490`，每项 8 字节 `{u32 序号, wchar_t* 名字}`，'
             '共 70 项。**不是解包文件里的 `download_list.csv`**。\n')
    L.append('> 生成脚本：`server/dump_client_table_list.py`。\n\n')
    L.append('| # | 序号 | 名字 | 路径（取自解包 CSV，仅用于对照） | 实测请求 |\n')
    L.append('|---|---|---|---|---|\n')
    for pos, idx, name in client:
        path = n2p.get(name, '—（CSV 里没有这个名字）—')
        got = '✅' if path in req else '—'
        L.append('| %d | %d | `%s` | `%s` | %s |\n' % (pos, idx, name, path, got))

    cn = [n for _, _, n in client]
    csvn = list(n2p)
    only_cli = [n for n in cn if n not in n2p]
    only_csv = [n for n in csvn if n not in cn]
    L.append('\n## 与解包 `download_list.csv` 的差异\n\n')
    L.append('- 客户端 **%d** 项；解包 CSV **%d** 行；名字交集 **%d**。\n'
             % (len(cn), len(csvn), len(set(cn) & set(csvn))))
    L.append('- **客户端有、CSV 没有**（%d）：%s\n'
             % (len(only_cli), '、'.join('`%s`' % x for x in only_cli)))
    L.append('- **CSV 有、客户端没有**（%d）：%s\n'
             % (len(only_csv), '、'.join('`%s`' % x for x in only_csv)))
    L.append('\n## 实际被请求的顺序（最新一轮）\n\n')
    L.append('客户端按**序号升序**走一遍，跳过 3 个序号（见下），'
             '走到 67 就因为该表加载失败而停住，68/69 永远轮不到。\n\n')
    for i, x in enumerate(rounds[-1] if rounds else [], 1):
        L.append('%d. `%s`\n' % (i, x))

    OUT.write_text(''.join(L), encoding='utf-8')
    print('wrote %s' % OUT)
    print('client=%d csv=%d common=%d' % (len(cn), len(csvn), len(set(cn) & set(csvn))))
    print('only_client=%s' % only_cli)
    print('only_csv=%s' % only_csv)
    return 0


if __name__ == '__main__':
    sys.exit(main())
