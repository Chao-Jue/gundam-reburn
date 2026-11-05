"""武器复核数据集：装配 + L1 图标层候选 + 复核服务。

- `--build`：把 Wiki 武器行、客户端武器外观、图标组装配成
  `server/reference/weapon_review/weapon_review.json`，所有边留空（unknown）。
- `--icons`：跑 L1，为每个 Wiki 图标组生成客户端图标候选（status=candidate）。
- 服务：人工采纳图标后写回 icon_pair，并把反推到的模型传播到该组所有行。

不写任何 weapon_settings，也不改客户端资源；人工 confirmed 的边不会被自动覆盖。
"""
import argparse
from collections import Counter, defaultdict
import csv
import io
from datetime import datetime, timezone
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import threading
from urllib.parse import urlparse, parse_qs
import webbrowser

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'GundamOnline_CHINA_已解密/decrypted'
OUT = ROOT / 'server/reference/weapon_review'
DATA = OUT / 'weapon_review.json'
SUMMARY = OUT / 'summary.json'
PAGE = Path(__file__).with_suffix('.html')
WIKI = ROOT / 'server/reference/wiki/units.json'

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / 'model_matcher'))
from dxg import parse as parse_dxg  # noqa: E402
import weapon_icon_layer as icon_layer  # noqa: E402

MODEL_PATH = re.compile(r'item/(\d{2})/(\d{4})/model/EM_\d{2}_\d{4}_(\d{2})\.dxg$')
ICON_CACHE = OUT / 'client_icons.npz'
ICON_FOLDER = OUT / 'icons'
LOCK = threading.RLock()
SUMMARY_EXTRA = {}


def now():
    return datetime.now(timezone.utc).isoformat()


def short_id(prefix, text):
    return '%s_%s' % (prefix, hashlib.sha1(text.encode('utf8')).hexdigest()[:10])


def image_name(weapon):
    for key, value in weapon['attributes'].items():
        if '图片名称' in key and isinstance(value, str) and value.strip():
            return value.strip()
    return None


def build_models():
    """客户端武器外观清单。n 条武器数据可共享一个模型，所以这里只记客户端事实。"""
    models, failures = {}, []
    for path in sorted((ASSETS / 'item').rglob('EM_*.dxg')):
        relative = path.relative_to(ASSETS).as_posix()
        found = MODEL_PATH.search(relative)
        if not found:
            continue
        a, b, c = found.groups()
        resource = int(a) * 1000000 + int(b) * 100 + int(c)
        key = '%02d%04d%02d' % (int(a), int(b), int(c))
        entry = {'dxg': relative, 'resource': resource, 'mesh': '',
                 'sockets': [], 'status': 'unknown'}
        try:
            parsed = parse_dxg(path.read_bytes())
        except Exception as error:
            entry['evidence'] = {'source': 'import', 'note': '解析失败: %s' % str(error)[:80]}
            failures.append({'model': key, 'error': str(error)[:80]})
        else:
            entry['mesh'] = ','.join(m['name'] for m in parsed['meshes'])[:160]
            entry['sockets'] = [s['name'] for s in parsed['sockets']]
            entry['dxg_version'] = parsed.get('version', '?')
        models[key] = entry
    return models, failures


def build(assets=ASSETS, wiki=WIKI):
    units = json.loads(Path(wiki).read_text('utf8'))['units']
    models, model_failures = build_models()

    icon_pairs, weapon_data = {}, {}
    stats = Counter()
    empty_units = []
    now = datetime.now(timezone.utc).isoformat()

    for unit in units:
        title = unit.get('title') or ''
        weapons = unit.get('weapons') or []
        if not weapons:
            empty_units.append(title)
            stats['units_without_weapons'] += 1
            continue
        stats['units'] += 1
        for index, weapon in enumerate(weapons):
            stats['rows'] += 1
            name = weapon.get('name') or weapon['attributes'].get('武器名称') or ''
            image = image_name(weapon)
            icon_key = None
            if image:
                icon_key = short_id('ip', image)
                if icon_key not in icon_pairs:
                    icon_pairs[icon_key] = {
                        'hangar': None, 'battle': None, 'status': 'unknown',
                        'evidence': {'source': 'icon_similarity', 'source_ref': image,
                                     'note': '按 Wiki 图片名称分组，尚未配对客户端图标'},
                    }
                    stats['icon_groups'] += 1
                else:
                    stats['rows_sharing_icon'] += 1
            else:
                stats['rows_without_icon'] += 1

            key = short_id('wd', '%s|%d' % (title, index))
            weapon_data[key] = {
                'id': key,
                'source': {'wiki_title': title, 'revision_id': unit.get('revision_id'),
                           'row_index': index, 'source_url': unit.get('source_url', ''),
                           'image_name': image},
                'name': name,
                'attributes': {k: v for k, v in weapon['attributes'].items()
                               if isinstance(v, str) and v.strip()},
                'model': None,
                'client_id': None,
                'icon_pair': icon_key,
                'effect_groups': [],
                'status': 'unknown',
                'updated_at_utc': now,
            }

    dataset = {
        'schema_version': 1,
        'generated_at_utc': now,
        'source_note': '由 tools/weapon_review.py 装配：Wiki 行 + 客户端外观 + 图标分组。'
                       '所有边留空（unknown），不含任何人工判定。',
        'models': models,
        'icon_pairs': icon_pairs,
        'effect_groups': {},
        'weapon_data': weapon_data,
        'review_log': [],
    }
    summary = {
        'rows': stats['rows'],
        'rows_with_icon': stats['rows'] - stats['rows_without_icon'],
        'rows_without_icon': stats['rows_without_icon'],
        'rows_sharing_icon': stats['rows_sharing_icon'],
        'icon_groups': stats['icon_groups'],
        'units_with_weapons': stats['units'],
        'units_without_weapons': stats['units_without_weapons'],
        'empty_unit_titles': empty_units,
        'models': len(models),
        'model_failures': model_failures,
        'effect_groups': 0,
        'edges': {'model': 0, 'icon': 0, 'effect': 0},
    }
    return dataset, summary


def load():
    if not DATA.exists():
        raise SystemExit('还没有数据集，先运行: python tools/weapon_review.py --build')
    return json.loads(DATA.read_text('utf8'))


@lru_cache(maxsize=1)
def cached():
    return load()


class Handler(BaseHTTPRequestHandler):
    def reply(self, value, status=200, content_type='application/json; charset=utf-8'):
        if not isinstance(value, bytes):
            value = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(value)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(value)

    def do_GET(self):
        try:
            request = urlparse(self.path)
            query = parse_qs(request.query)
            if request.path == '/api/review':
                return self.reply(cached())
            if request.path == '/api/summary':
                if not SUMMARY.exists():
                    return self.reply({'error': '没有 summary.json，先 --build'}, 404)
                return self.reply(json.loads(SUMMARY.read_text('utf8')))
            if request.path == '/api/icon':
                target = query.get('path', [''])[0]
                validate_icon(target)
                return self.reply(png_bytes(ASSETS / target), content_type='image/png')
            if request.path == '/api/wiki':
                key = query.get('pair', [''])[0]
                dataset = cached()
                pair = dataset['icon_pairs'].get(key) or {}
                name = (pair.get('evidence') or {}).get('source_ref')
                if not name:
                    raise ValueError('该图标组没有 Wiki 图片')
                path = icon_layer.fetch_icon(name, None, ICON_FOLDER)
                if path is None:
                    raise ValueError('Wiki 图片未下载，先跑 --icons')
                return self.reply(png_bytes(path), content_type='image/png')
            if request.path in ('/', '/index.html'):
                return self.reply(PAGE.read_bytes(), content_type='text/html; charset=utf-8')
            return self.reply({'error': 'not found'}, 404)
        except Exception as error:
            self.reply({'error': str(error)}, 400)

    def do_POST(self):
        try:
            if urlparse(self.path).path != '/api/icon':
                return self.reply({'error': 'not found'}, 404)
            origin = self.headers.get('Origin')
            if origin and origin != 'http://' + self.headers.get('Host', ''):
                raise ValueError('不接受跨站写入')
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length < 20000:
                raise ValueError('请求长度无效')
            body = json.loads(self.rfile.read(length))
            pair = body.get('pair', '')
            if pair not in cached()['icon_pairs']:
                raise ValueError('图标组不存在')
            hangar = body.get('hangar') or None
            battle = body.get('battle') or None
            if hangar:
                validate_icon(hangar)
            if battle:
                validate_icon(battle)
            with LOCK:
                dataset = load()
                accept_icon(dataset, pair, hangar, battle, body.get('note', ''))
                save(dataset)
                cached.cache_clear()
            self.reply(current_summary(dataset))
        except Exception as error:
            self.reply({'error': str(error)}, 400)


def validate_icon(relative):
    if not relative.startswith('interface/icon/'):
        raise ValueError('图标路径必须在 interface/icon/ 下')
    path = (ASSETS / relative).resolve()
    if not path.is_file() or not path.is_relative_to(ASSETS.resolve()):
        raise ValueError('图标文件不存在')
    if path.suffix.lower() not in ('.dds', '.png'):
        raise ValueError('不支持的图标格式')


@lru_cache(maxsize=600)
def png_bytes(path):
    with Image.open(path) as image:
        image = image.convert('RGBA')
        image.thumbnail((240, 120))
        buffer = io.BytesIO()
        image.save(buffer, 'PNG')
    return buffer.getvalue()


def accept_icon(dataset, pair_key, hangar, battle, note=''):
    """人工采纳一组图标：写回 pair，并把反推的模型传播到该组所有行。"""
    pair = dataset['icon_pairs'][pair_key]
    vector = icon_layer.model_from_icon(Path(hangar).stem) if hangar else None
    model = vector if vector in dataset['models'] else None
    pair['hangar'] = hangar
    pair['battle'] = battle
    # 清除不是清成 unknown：如果还有机器候选，应退回 candidate
    pair['status'] = 'confirmed' if hangar else ('candidate' if pair.get('candidates') else 'unknown')
    pair['evidence'] = {'source': 'manual' if hangar else 'import',
                        'source_ref': pair['evidence'].get('source_ref', ''),
                        'note': note or '人工采纳'}
    pair['updated_at_utc'] = now()
    affected = 0
    for row in dataset['weapon_data'].values():
        if row['icon_pair'] != pair_key:
            continue
        affected += 1
        if hangar:
            row['model'] = model
        else:
            row['model'] = None
    dataset['review_log'].append({
        'at_utc': now(), 'action': 'set' if hangar else 'clear',
        'target': 'icon_pairs:%s' % pair_key, 'to': hangar,
        'note': '影响 %d 行；反推模型 %s' % (affected, model or '无')})
    recompute(dataset)
    return affected, model


def recompute(dataset):
    """按三条边的状态重算每行状态与全局进度。"""
    confirmed_icons = {k for k, v in dataset['icon_pairs'].items() if v.get('status') == 'confirmed'}
    confirmed_groups = {k for k, v in dataset['effect_groups'].items() if v.get('status') == 'confirmed'}
    for row in dataset['weapon_data'].values():
        has_model = bool(row['model'])
        has_icon = row['icon_pair'] in confirmed_icons
        has_effect = any(g in confirmed_groups for g in row['effect_groups'])
        if has_model and has_icon and has_effect:
            row['status'] = 'confirmed'
        elif has_model or has_icon or has_effect:
            row['status'] = 'candidate'
        else:
            row['status'] = 'unknown'
    return current_summary(dataset)


def current_summary(dataset):
    rows = list(dataset['weapon_data'].values())
    pairs = list(dataset['icon_pairs'].values())
    return {
        'rows': len(rows),
        'rows_with_model': sum(1 for r in rows if r['model']),
        'rows_confirmed': sum(1 for r in rows if r['status'] == 'confirmed'),
        'rows_candidate': sum(1 for r in rows if r['status'] == 'candidate'),
        'icon_groups': len(pairs),
        'icons_confirmed': sum(1 for p in pairs if p.get('status') == 'confirmed'),
        'icons_candidate': sum(1 for p in pairs if p.get('status') == 'candidate'),
        'models': len(dataset['models']),
        'effect_groups': len(dataset['effect_groups']),
    }


def save(dataset):
    """写数据集 + 汇总。

    summary 是旁挂文件，除了当前统计还要保留装配阶段才有的缺口清单
    （空武器表机体、解析失败的模型）。服务端进程也可能写它，
    所以要以磁盘上已有内容为底，不能只用内存里的 SUMMARY_EXTRA。
    """
    temporary = DATA.with_suffix('.tmp')
    temporary.write_text(json.dumps(dataset, ensure_ascii=False, indent=1), 'utf8')
    temporary.replace(DATA)
    summary = {}
    if SUMMARY.exists():
        try:
            summary = json.loads(SUMMARY.read_text('utf8'))
        except Exception:
            summary = {}
    summary.update(SUMMARY_EXTRA)
    summary.update(current_summary(dataset))
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2), 'utf8')


def read_client_csv(path):
    """读国服武器对照表（GBK）。返回行列表；列名：国服页名/行序/武装名/客户端号/状态。"""
    raw = Path(path).read_bytes()
    for encoding in ('gbk', 'gb18030', 'utf-8-sig'):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise ValueError('对照表编码无法识别')
    return list(csv.DictReader(io.StringIO(text)))


def import_client_ids(dataset, csv_path, assets=ASSETS):
    """导入「武器数据 → 客户端号」。

    连接键是 (国服页名, 行序)，行序从 1 开始；实测 5848/5855 行能对上且武装名一致。
    客户端号主要索引图标（s<号>.dds），约一半同时是模型号（item/.. EM_..<号>.dxg 末八位）。
    图标组只有在组内号唯一时才写回，多号组记 conflict，不猜。
    """
    rows = read_client_csv(csv_path)
    by_pos = {(r['source']['wiki_title'], r['source']['row_index'] + 1): r
              for r in dataset['weapon_data'].values()}
    icons = {p.stem[1:] for p in (Path(assets) / 'interface/icon/item/s').glob('s*.dds')}
    battles = {p.stem[1:] for p in (Path(assets) / 'interface/icon/battle/b').glob('b*.dds')}
    stats = Counter()
    group_ids = defaultdict(set)
    unmatched_pages = set()
    for row in rows:
        title = (row.get('国服页名') or '').strip()
        try:
            index = int((row.get('行序') or '').strip())
        except ValueError:
            continue
        target = by_pos.get((title, index))
        if target is None:
            stats['unmatched'] += 1
            unmatched_pages.add(title)
            continue
        if (row.get('武装名') or '').strip() and (row.get('武装名') or '').strip() != target['name'].strip():
            stats['name_mismatch'] += 1
            continue
        client_id = (row.get('客户端号') or '').strip()
        if not client_id:
            stats['no_id'] += 1
            continue
        stats['matched'] += 1
        target['client_id'] = client_id
        target['notes'] = (target.get('notes') or '') + ('对照表: %s; ' % (row.get('状态') or '')).strip()
        if client_id in dataset['models']:
            target['model'] = client_id
            stats['model'] += 1
        if target['icon_pair']:
            group_ids[target['icon_pair']].add(client_id)
    uniform = mixed = 0
    for key, ids in group_ids.items():
        pair = dataset['icon_pairs'][key]
        if len(ids) == 1:
            client_id = next(iter(ids))
            hangar = 'interface/icon/item/s/s%s.dds' % client_id if client_id in icons else None
            battle = 'interface/icon/battle/b/b%s.dds' % client_id if client_id in battles else None
            if hangar:
                pair['hangar'] = hangar
                pair['battle'] = battle
                pair['status'] = 'confirmed'
                pair['evidence'] = {'source': 'import', 'score': None,
                                    'source_ref': pair['evidence'].get('source_ref', ''),
                                    'note': '来自国服武器对照表（组内客户端号唯一）'}
                uniform += 1
        else:
            pair['status'] = 'conflict'
            pair['evidence'] = {'source': 'import', 'score': None,
                                'source_ref': pair['evidence'].get('source_ref', ''),
                                'note': '组内出现 %d 个不同客户端号：%s'
                                        % (len(ids), ', '.join(sorted(ids)[:6]))}
            mixed += 1
    stats['icon_uniform'] = uniform
    stats['icon_mixed'] = mixed
    stats['unmatched_pages'] = len(unmatched_pages)
    dataset['review_log'].append({
        'at_utc': now(), 'action': 'bulk_set', 'target': 'weapon_data:*.client_id',
        'note': '导入国服对照表：匹配 %d 行，写入模型 %d，图标组统一 %d、冲突 %d'
                % (stats['matched'], stats['model'], uniform, mixed)})
    recompute(dataset)
    return stats


EXPORT_FIELDS = ['国服页名', '行序', '武器名', '射击模式', '客户端号', '模型键', '模型路径',
                 '网格', '挂点', '格纳库图标', '战场图标', '图标来源', '数据状态']


def link_records(dataset):
    """把嵌套数据集拍平成「一行武器数据一条记录」，供导出和下游直接消费。

    原则：只搬运已有事实。没有 client_id / model / 图标的行留空字符串，
    不用 0 或占位符填空，免得下游把缺数据当成真值。
    """
    models = dataset['models']
    pairs = dataset['icon_pairs']
    records = []
    rows = sorted(dataset['weapon_data'].values(),
                  key=lambda r: (r['source']['wiki_title'], r['source']['row_index']))
    for row in rows:
        model = models.get(row.get('model') or '') or {}
        pair = pairs.get(row.get('icon_pair') or '') or {}
        confirmed = pair.get('status') == 'confirmed'
        records.append({
            '国服页名': row['source']['wiki_title'],
            '行序': row['source']['row_index'] + 1,
            '武器名': row['name'],
            '射击模式': row['attributes'].get('射击模式', ''),
            '客户端号': row.get('client_id') or '',
            '模型键': row.get('model') or '',
            '模型路径': model.get('dxg', ''),
            '网格': model.get('mesh', ''),
            '挂点': ' '.join(model.get('sockets') or []),
            '格纳库图标': (pair.get('hangar') or '') if confirmed else '',
            '战场图标': (pair.get('battle') or '') if confirmed else '',
            '图标来源': (pair.get('evidence') or {}).get('source', '') if confirmed else '',
            '数据状态': row['status'],
        })
    return records


def fill_icons_by_client_id(dataset, assets=ASSETS):
    """客户端号能直接确定图标文件时，按号建一对图标并挂到该行。

    这一步不是猜：`s<号>.dds` 存在就是存在，不存在就不写。
    主要覆盖「没有 Wiki 图片名称、因此没有图标组」的行——它们以前永远拿不到图标。
    """
    icons = {p.stem[1:] for p in (Path(assets) / 'interface/icon/item/s').glob('s*.dds')}
    battles = {p.stem[1:] for p in (Path(assets) / 'interface/icon/battle/b').glob('b*.dds')}
    created = assigned = 0
    for row in dataset['weapon_data'].values():
        client_id = row.get('client_id')
        if not client_id or row.get('icon_pair') or client_id not in icons:
            continue
        key = 'ip_id_%s' % client_id
        if key not in dataset['icon_pairs']:
            dataset['icon_pairs'][key] = {
                'hangar': 'interface/icon/item/s/s%s.dds' % client_id,
                'battle': ('interface/icon/battle/b/b%s.dds' % client_id)
                          if client_id in battles else None,
                'status': 'confirmed',
                'evidence': {'source': 'import', 'score': None, 'source_ref': client_id,
                             'note': '由客户端号直读图标文件（无 Wiki 图片名称，按号成组）'},
                'updated_at_utc': now(),
            }
            created += 1
        row['icon_pair'] = key
        assigned += 1
    dataset['review_log'].append({
        'at_utc': now(), 'action': 'bulk_set', 'target': 'weapon_data:*.icon_pair',
        'note': '按客户端号直读图标：新建 %d 组、挂载 %d 行' % (created, assigned)})
    recompute(dataset)
    return created, assigned


def export_links(dataset, out_dir):
    """写 weapon_links.csv（带 BOM，Excel 直接打开）和 weapon_links.json。"""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    records = link_records(dataset)
    csv_path = out / 'weapon_links.csv'
    with open(csv_path, 'w', encoding='utf-8-sig', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=EXPORT_FIELDS)
        writer.writeheader()
        writer.writerows(records)
    stats = Counter()
    for record in records:
        stats['rows'] += 1
        if record['客户端号']:
            stats['with_client_id'] += 1
        if record['模型键']:
            stats['with_model'] += 1
        if record['格纳库图标']:
            stats['with_icon'] += 1
    json_path = out / 'weapon_links.json'
    json_path.write_text(json.dumps({
        'schema_version': 1,
        'generated_at_utc': now(),
        'source': 'server/reference/weapon_review/weapon_review.json',
        'note': '一行一条武器数据；空字符串表示尚未确定，不是 0。模型/图标只搬已确认的边。',
        'fields': EXPORT_FIELDS,
        'stats': dict(stats),
        'records': records,
    }, ensure_ascii=False, indent=1), 'utf8')
    return stats, csv_path, json_path


def run_icon_layer(dataset):
    """跑 L1：为所有图标组生成候选候选，合并进数据集（不覆盖 confirmed）。"""
    pairs = {k: v for k, v in dataset['icon_pairs'].items() if v.get('status') != 'confirmed'}
    names = sorted({(v.get('evidence') or {}).get('source_ref') for v in pairs.values()} - {None})
    print('L1：%d 个图标组（跳过已确认 %d 组）'
          % (len(names), len(dataset['icon_pairs']) - len(pairs)), flush=True)
    result, stats = icon_layer.match_icons(names, ASSETS, ICON_FOLDER, ICON_CACHE)
    print('  取到 URL %d 张，下载成功 %d，缺失 %d'
          % (stats['urls'], stats['downloaded'], len(stats['missing'])), flush=True)
    by_name = {}
    for key, pair in pairs.items():
        name = (pair.get('evidence') or {}).get('source_ref')
        if name:
            by_name.setdefault(name, []).append(key)
    applied = 0
    for name, payload in result.items():
        candidates = payload.get('candidates') or []
        battles = payload.get('battle_candidates') or []
        for key in by_name.get(name, []):
            pair = dataset['icon_pairs'][key]
            pair['candidates'] = candidates
            pair['battle_candidates'] = battles
            pair['status'] = 'candidate'
            pair['evidence'] = {
                'source': 'icon_similarity',
                'score': candidates[0]['score'] if candidates else None,
                'source_ref': name,
                'note': '仓图标与战图标各自前 %d 个候选；距离越低越像，不是概率'
                        % max(len(candidates), len(battles)),
            }
            pair['updated_at_utc'] = now()
            applied += 1
    dataset['review_log'].append({
        'at_utc': now(), 'action': 'bulk_set', 'target': 'icon_pairs:*',
        'note': 'L1 生成候选 %d 组，缺失 %d' % (applied, len(stats['missing']))})
    recompute(dataset)
    return applied, stats


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', action='store_true', help='重新装配数据集')
    parser.add_argument('--icons', action='store_true', help='跑 L1 图标层并写回候选')
    parser.add_argument('--import-csv', type=Path, default=None,
                        help='导入国服武器对照表（GBK CSV），写 client_id / 模型 / 图标')
    parser.add_argument('--fill-icons', action='store_true',
                        help='客户端号能确定图标文件的行，按号建图标组并挂上')
    parser.add_argument('--export', action='store_true',
                        help='导出扁平的 weapon_links.csv / .json 供下游使用')
    parser.add_argument('--export-dir', type=Path, default=OUT / 'export')
    parser.add_argument('--port', type=int, default=8770)
    parser.add_argument('--open', action='store_true')
    args = parser.parse_args()

    if args.build or not DATA.exists():
        print('装配：Wiki 行 + 客户端外观 + 图标分组...', flush=True)
        dataset, summary = build()
        global SUMMARY_EXTRA
        SUMMARY_EXTRA = {k: summary[k] for k in
                         ('rows_with_icon', 'rows_without_icon', 'rows_sharing_icon',
                          'units_with_weapons', 'units_without_weapons',
                          'empty_unit_titles', 'model_failures')}
        OUT.mkdir(parents=True, exist_ok=True)
        save(dataset)
        print('武器数据 %d 行（有图标 %d / 无图标 %d），图标组 %d，模型 %d（失败 %d），'
              '空武器表机体 %d'
              % (summary['rows'], summary['rows_with_icon'], summary['rows_without_icon'],
                 summary['icon_groups'], summary['models'], len(summary['model_failures']),
                 summary['units_without_weapons']), flush=True)
        print('写出', DATA, flush=True)
        if not args.icons and not args.open and args.port == 0:
            return

    if args.import_csv:
        dataset = load()
        stats = import_client_ids(dataset, args.import_csv)
        save(dataset)
        cached.cache_clear()
        print('导入完成：匹配 %d 行（未匹配 %d，名字不一致 %d），写入模型 %d，'
              '图标组统一 %d / 冲突 %d，未匹配页名 %d'
              % (stats['matched'], stats['unmatched'], stats['name_mismatch'],
                 stats['model'], stats['icon_uniform'], stats['icon_mixed'],
                 stats['unmatched_pages']), flush=True)
        if not args.icons and not args.open and args.port == 0:
            return

    if args.fill_icons:
        dataset = load()
        created, assigned = fill_icons_by_client_id(dataset)
        save(dataset)
        cached.cache_clear()
        print('按客户端号补图标：新建 %d 组、挂载 %d 行' % (created, assigned), flush=True)
        if not args.export and not args.open and args.port == 0:
            return

    if args.export:
        dataset = load()
        stats, csv_path, json_path = export_links(dataset, args.export_dir)
        print('导出 %d 行：有客户端号 %d、有模型 %d、有图标 %d'
              % (stats['rows'], stats['with_client_id'], stats['with_model'], stats['with_icon']),
              flush=True)
        print('  ', csv_path, flush=True)
        print('  ', json_path, flush=True)
        if not args.open and args.port == 0:
            return

    if args.icons:
        dataset = load()
        if not SUMMARY_EXTRA and SUMMARY.exists():
            SUMMARY_EXTRA = json.loads(SUMMARY.read_text('utf8'))
        applied, stats = run_icon_layer(dataset)
        save(dataset)
        cached.cache_clear()
        print('L1 完成：%d 组有候选，缺失 %d' % (applied, len(stats['missing'])), flush=True)
        if not args.open and args.port == 0:
            return

    print('http://127.0.0.1:%d' % args.port, flush=True)
    if args.open:
        threading.Timer(0.6, lambda: webbrowser.open('http://127.0.0.1:%d' % args.port)).start()
    ThreadingHTTPServer(('127.0.0.1', args.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
