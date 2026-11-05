"""按「机体」汇总：机体本身 + MSM 模型 + 武器行（含客户端号/武器模型/两套图标）。

数据来源都是已有结果，这里只做归并与导出，不新增任何判定：
- `server/reference/wiki/units.json`            机体页与武器表
- `server/reference/wiki/unit_images.json`      机体立绘 URL
- `server/reference/model_matches.json`         人工确认的 MSM 机体模型
- `server/reference/weapon_review/weapon_review.json`  武器行 → 客户端号 / 武器模型 / 图标

输出（`server/reference/unit_export/`）：
- `units.json`       按机体嵌套，包含上面四类字段
- `units.csv`        一行一条武器，机体字段重复展开（Excel 直接看）
- `unit_index.csv`   一行一个机体，带各项计数
- `completeness.json` 覆盖率与缺口清单
"""
import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / 'server/reference'


def now():
    return datetime.now(timezone.utc).isoformat()


def invert_model_matches(matches):
    """model_matches 是「模型→机体列表」，反过来给每个机体页找到 MSM 模型。"""
    by_unit = {}
    for entry in matches.values():
        path = entry.get('model_path') or ''
        for unit in entry.get('units') or []:
            title = unit.get('title')
            if not title:
                continue
            by_unit.setdefault(title, []).append({
                'model_path': path,
                'model_id': entry.get('model_id'),
                'model_sha256': entry.get('model_sha256'),
                'matched_units': [u.get('title') for u in entry.get('units') or []],
            })
    return by_unit


def build_units(units, images, matches, dataset):
    """纯归并函数，便于测试。返回 (机体列表, 统计)。"""
    models = dataset['models']
    pairs = dataset['icon_pairs']
    rows_by_unit = defaultdict(list)
    for row in dataset['weapon_data'].values():
        rows_by_unit[row['source']['wiki_title']].append(row)

    by_unit_model = invert_model_matches(matches)
    portraits = images.get('images') or {}

    result = []
    stats = Counter()
    for unit in units:
        title = unit.get('title') or ''
        weapons = []
        for row in sorted(rows_by_unit.get(title, []), key=lambda r: r['source']['row_index']):
            model = models.get(row.get('model') or '') or {}
            pair = pairs.get(row.get('icon_pair') or '') or {}
            confirmed = pair.get('status') == 'confirmed'
            weapons.append({
                'row': row['source']['row_index'] + 1,
                'name': row['name'],
                'attributes': row['attributes'],
                'client_id': row.get('client_id') or None,
                'model': {
                    'key': row['model'],
                    'dxg': model.get('dxg'),
                    'mesh': model.get('mesh'),
                    'sockets': model.get('sockets') or [],
                } if row.get('model') else None,
                'icons': {
                    'hangar': pair.get('hangar'),
                    'battle': pair.get('battle'),
                    'source': (pair.get('evidence') or {}).get('source'),
                } if confirmed else None,
                'status': row['status'],
            })

        unit_models = by_unit_model.get(title) or []
        portrait = portraits.get(title) or {}
        record = {
            'page': title,
            'revision_id': unit.get('revision_id'),
            'source_url': unit.get('source_url', ''),
            'portrait_url': portrait.get('url'),
            'unit_model': unit_models[0] if unit_models else None,
            'weapons': weapons,
            'counts': {
                'weapons': len(weapons),
                'with_client_id': sum(1 for w in weapons if w['client_id']),
                'with_model': sum(1 for w in weapons if w['model']),
                'with_icons': sum(1 for w in weapons if w['icons']),
            },
        }
        result.append(record)
        stats['units'] += 1
        stats['weapons'] += record['counts']['weapons']
        stats['with_client_id'] += record['counts']['with_client_id']
        stats['with_model'] += record['counts']['with_model']
        stats['with_icons'] += record['counts']['with_icons']
        if unit_models:
            stats['units_with_model'] += 1
        if portrait.get('url'):
            stats['units_with_portrait'] += 1
        if not weapons:
            stats['units_without_weapons'] += 1
    stats['units'] = len(result)
    return result, stats


def write_all(units, stats, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    (out / 'units.json').write_text(json.dumps({
        'schema_version': 1,
        'generated_at_utc': now(),
        'note': '按机体汇总：机体页 + MSM 模型 + 武器行（客户端号/武器模型/两套图标）。'
                '字段为 null 表示尚未确定，不是空值占位。',
        'stats': dict(stats),
        'units': units,
    }, ensure_ascii=False, indent=1), 'utf8')

    flat_fields = ['国服页名', 'revision_id', '机体立绘', 'MSM模型路径', 'MSM模型ID',
                   '行序', '武器名', '射击模式', '威力', '弹数', '客户端号',
                   '武器模型键', '武器模型路径', '挂点', '格纳库图标', '战场图标', '图标来源', '状态']
    with open(out / 'units.csv', 'w', encoding='utf-8-sig', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=flat_fields)
        writer.writeheader()
        for unit in units:
            model = unit['unit_model'] or {}
            base = {'国服页名': unit['page'], 'revision_id': unit['revision_id'] or '',
                    '机体立绘': unit['portrait_url'] or '',
                    'MSM模型路径': model.get('model_path', ''),
                    'MSM模型ID': model.get('model_id', '')}
            if not unit['weapons']:
                writer.writerow(base)
                continue
            for weapon in unit['weapons']:
                weapon_model = weapon['model'] or {}
                icons = weapon['icons'] or {}
                writer.writerow({**base,
                                 '行序': weapon['row'],
                                 '武器名': weapon['name'],
                                 '射击模式': weapon['attributes'].get('射击模式', ''),
                                 '威力': weapon['attributes'].get('威力', ''),
                                 '弹数': weapon['attributes'].get('弹数', ''),
                                 '客户端号': weapon['client_id'] or '',
                                 '武器模型键': weapon_model.get('key', ''),
                                 '武器模型路径': weapon_model.get('dxg', ''),
                                 '挂点': ' '.join(weapon_model.get('sockets') or []),
                                 '格纳库图标': icons.get('hangar', ''),
                                 '战场图标': icons.get('battle') or '',
                                 '图标来源': icons.get('source', ''),
                                 '状态': weapon['status']})

    with open(out / 'unit_index.csv', 'w', encoding='utf-8-sig', newline='') as handle:
        fields = ['国服页名', '武器数', '有客户端号', '有武器模型', '有图标',
                  '有MSM模型', 'MSM模型路径', '有立绘']
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for unit in units:
            counts = unit['counts']
            writer.writerow({'国服页名': unit['page'], '武器数': counts['weapons'],
                             '有客户端号': counts['with_client_id'],
                             '有武器模型': counts['with_model'],
                             '有图标': counts['with_icons'],
                             '有MSM模型': 'Y' if unit['unit_model'] else '',
                             'MSM模型路径': (unit['unit_model'] or {}).get('model_path', ''),
                             '有立绘': 'Y' if unit['portrait_url'] else ''})

    gaps = {
        'units_without_ms_model': [u['page'] for u in units if not u['unit_model']],
        'units_without_weapons': [u['page'] for u in units if not u['weapons']],
        'units_without_portrait': [u['page'] for u in units if not u['portrait_url']],
        'weapons_without_model': [
            {'page': u['page'], 'row': w['row'], 'name': w['name'], 'client_id': w['client_id']}
            for u in units for w in u['weapons'] if not w['model']],
        'weapons_without_icons': [
            {'page': u['page'], 'row': w['row'], 'name': w['name'], 'client_id': w['client_id']}
            for u in units for w in u['weapons'] if not w['icons']],
    }
    (out / 'completeness.json').write_text(json.dumps({
        'generated_at_utc': now(),
        'stats': dict(stats),
        'gap_counts': {k: len(v) for k, v in gaps.items()},
        'gaps': gaps,
    }, ensure_ascii=False, indent=1), 'utf8')
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=REF / 'unit_export')
    args = parser.parse_args()

    units = json.loads((REF / 'wiki/units.json').read_text('utf8'))['units']
    images = json.loads((REF / 'wiki/unit_images.json').read_text('utf8'))
    matches = json.loads((REF / 'model_matches.json').read_text('utf8'))['matches']
    dataset = json.loads((REF / 'weapon_review/weapon_review.json').read_text('utf8'))

    records, stats = build_units(units, images, matches, dataset)
    out = write_all(records, stats, args.out)
    print('机体 %d：有 MSM 模型 %d、有立绘 %d、无武器表 %d'
          % (stats['units'], stats['units_with_model'], stats['units_with_portrait'],
             stats['units_without_weapons']), flush=True)
    print('武器行 %d：有客户端号 %d、有模型 %d、有图标 %d'
          % (stats['weapons'], stats['with_client_id'], stats['with_model'],
             stats['with_icons']), flush=True)
    print('写出', out, flush=True)


if __name__ == '__main__':
    main()
