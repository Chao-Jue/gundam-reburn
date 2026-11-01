#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""武器解锁命令行：把已定义但未持有的测试武器写进机体记录并落盘。

用法：
    # 看有哪些武器、哪些已解锁
    python tools/unlock_weapon.py --list

    # 解锁一把（账号 123 / 机师 1 / 机体 777000000001）
    python tools/unlock_weapon.py --account 123 --pilot 1 --uniqid 777000000001 --item-id 777105

    # 一次解锁多把
    python tools/unlock_weapon.py --account 123 --pilot 1 --uniqid 777000000001 --item-id 777105,777108

说明：
- 解锁 = 写进 unit['weapons']，与机师/机体一起存在 server/saved_hangar.gm.json；
- 幂等：已解锁的会跳过并提示；
- 只影响实验存档（默认 --store server/saved_hangar.gm.json），普通模式存档不动。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server'))

import hangar_experiment as experiment  # noqa: E402
from hangar import HangarStore  # noqa: E402

DEFAULT_STORE = ROOT / 'server' / 'saved_hangar.gm.json'


def show(store, account, pilot):
    units = store.units(account, pilot) if account and pilot else []
    owned = set()
    for unit in units:
        owned |= {w['item_id'] for w in unit.get('weapons', [])}
    print('武器定义（%d 把，其中 starter %d 把默认授予）：'
          % (len(experiment.all_definitions()), len(experiment.starter_definitions())))
    for weapon in experiment.all_definitions():
        mark = '已解锁' if weapon['item_id'] in owned else '-- 未解锁'
        print('  %d  %-14s %-11s %s'
              % (weapon['item_id'], weapon['name'], weapon['kind'], mark))
    if units:
        for unit in units:
            print('机体 %d 持有: %s' % (unit['uniqid'],
                                      [w['item_id'] for w in unit.get('weapons', [])]))
            print('           装备: %s' % unit.get('equipped_weapons'))
            sets = unit.get('equipsets', [])
            print('           装备组: %s' % ('无' if not sets else ''))
            for entry in sets:
                print('             [%d] %-12s 武器=%s 盾=%s'
                      % (entry.get('slot', 0), entry.get('name', ''), entry.get('weapons'),
                         entry.get('shield')))
    else:
        print('（该账号/机师还没有实验机体存档）')


def main(argv=None):
    parser = argparse.ArgumentParser(description='解锁实验用测试武器并持久化')
    parser.add_argument('--store', default=str(DEFAULT_STORE))
    parser.add_argument('--account', default=None)
    parser.add_argument('--pilot', type=int, default=None)
    parser.add_argument('--uniqid', type=int, default=None)
    parser.add_argument('--item-id', default=None, help='逗号分隔的 item_id 列表')
    parser.add_argument('--lock', action='store_true',
                        help='反向操作：把武器退回未解锁（并清掉引用它的装备槽）')
    parser.add_argument('--list', action='store_true', help='只列出定义与解锁状态')
    args = parser.parse_args(argv)

    store = HangarStore(args.store)
    if args.list or not args.item_id:
        show(store, args.account, args.pilot)
        if not args.item_id:
            return 0

    if not (args.account and args.pilot and args.uniqid):
        parser.error('解锁需要同时给 --account/--pilot/--uniqid')

    failed = 0
    for raw in args.item_id.split(','):
        raw = raw.strip()
        if not raw:
            continue
        item_id = int(raw, 0)
        try:
            if args.lock:
                changed = experiment.lock_weapon(store, args.account, args.pilot,
                                                 args.uniqid, item_id)
                print('  %s %d' % ('[-] 已退回未解锁' if changed else '[=] 本来就没有', item_id))
            else:
                changed = experiment.unlock_weapon(store, args.account, args.pilot,
                                                   args.uniqid, item_id)
                print('  %s %d' % ('[+] 已解锁' if changed else '[=] 本来就有', item_id))
        except ValueError as error:
            print('  [!] %d 操作失败: %s' % (item_id, error))
            failed += 1

    print('存档: %s' % Path(args.store))
    show(store, args.account, args.pilot)
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
