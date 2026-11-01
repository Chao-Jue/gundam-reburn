"""Cache Biligame unit references through its public MediaWiki API.

Reference values and Wiki page IDs are never treated as client/server IDs.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request
import unicodedata

API = 'https://wiki.biligame.com/gundam/api.php'
PROPERTIES = ('名称', '势力', '类型', 'COST', 'TIME', '装甲', '盾牌', '最高速度',
              '推进容量', '推进器冷却', '载重量', '紧急归投数量', '机体倒地值')


def split_top(text, delimiter='|'):
    parts, start, braces, links, i = [], 0, 0, 0, 0
    while i < len(text):
        pair = text[i:i + 2]
        if pair in ('{{', '}}', '[[', ']]'):
            if pair == '{{': braces += 1
            elif pair == '}}': braces -= 1
            elif pair == '[[': links += 1
            else: links -= 1
            i += 2
            continue
        if text[i] == delimiter and braces == 0 and links == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    return parts + [text[start:]]


def templates(text):
    # Include nested templates too, preserving their original field text.
    text = re.sub(r'<!--.*?-->', '', text, flags=re.S)
    stack, result = [], []
    for match in re.finditer(r'\{\{|\}\}', text):
        if match.group() == '{{':
            stack.append(match.end())
        elif stack:
            start = stack.pop()
            chunks = split_top(text[start:match.start()])
            fields = {}
            for chunk in chunks[1:]:
                if '=' in chunk:
                    key, value = chunk.split('=', 1)
                    fields[key.strip()] = value.strip()
            result.append({'template': chunks[0].strip(), 'fields': fields,
                           'offset': start - 2})
    return sorted(result, key=lambda item: item['offset'])


def parse_unit(title, url, revision_id, text):
    parsed = templates(text)
    basic = [t for t in parsed if '名称' in t['fields'] and 'COST' in t['fields']]
    weapons = []
    for item in parsed:
        fields = item['fields']
        if '武器名称' in fields:
            flag = fields.get('是否金限')
            weapons.append({'name': fields['武器名称'],
                            'gold_only': True if flag == '1' else False if flag == '0' else None,
                            'template': item['template'], 'attributes': fields})
    # Older pages use handwritten tables rather than templates. Preserve their
    # cells separately instead of pretending they were normalized weapons.
    tables = []
    for match in re.finditer(r'\{\|([^\n]*)\n(.*?)\n\|\}', text, re.S):
        rows = []
        for raw_row in re.split(r'\n\|-.*?\n', '\n' + match.group(2)):
            cells = []
            for line in raw_row.splitlines():
                if line.startswith(('|', '!')) and not line.startswith(('|+', '|-', '|}')):
                    cells.extend(cell.strip() for cell in re.split(r'\|\||!!', line[1:]))
            if cells: rows.append(cells)
        tables.append({'attributes': match.group(1).strip(), 'rows': rows})
    return {'title': title, 'source_url': url, 'revision_id': revision_id,
            'client_unit_id': None, 'client_weapon_ids_verified': False,
            'stats': basic[0]['fields'] if basic else {}, 'weapons': weapons,
            'tables': tables, 'templates': parsed}


def reference_name(title):
    name = unicodedata.normalize('NFKC', title)
    for part in ('高达OL', '敢达OL', '机体数据', '机体模板'):
        name = name.replace(part, '')
    return name.strip()


def enrich_unit(unit, catalog):
    matches = [entry for title, entry in catalog.items()
               if reference_name((entry.get('printouts', {}).get('名称') or [title])[0])
               == reference_name(unit['title'])]
    if len(matches) == 1:
        unit['reference_printouts'] = matches[0]['printouts']
        unit['stats_source_url'] = matches[0]['fullurl']
        if not unit['stats']:
            unit['stats'] = {k: v[0] for k, v in matches[0]['printouts'].items() if len(v) == 1}
    unit['weapon_extraction'] = ('templates' if unit['weapons'] else
                                'legacy_tables_need_mapping' if unit['tables'] else 'unavailable')
    return unit


def complete_catalog(units, catalog):
    """Keep category-only definitions visible without inventing missing weapons."""
    units = list(units)
    known = {reference_name(u.get('stats', {}).get('名称') or u['title']) for u in units}
    for title, entry in catalog.items():
        name = (entry.get('printouts', {}).get('名称') or [title])[0]
        if reference_name(name) in known:
            continue
        unit = parse_unit(title, entry['fullurl'], None, '')
        unit['stats'] = {k: v[0] for k, v in entry.get('printouts', {}).items() if len(v) == 1}
        unit.update(reference_name=reference_name(name), aliases=[name],
                    data_completeness='catalog_only', weapon_extraction='unavailable',
                    reference_printouts=entry.get('printouts', {}))
        units.append(unit)
        known.add(reference_name(name))
    return units


class WikiClient:
    def __init__(self, folder):
        self.folder = folder
        folder.mkdir(parents=True, exist_ok=True)

    def get(self, **params):
        params['format'] = 'json'
        url = API + '?' + urllib.parse.urlencode(params)
        path = self.folder / (hashlib.sha256(url.encode()).hexdigest() + '.json')
        if path.exists():
            return json.loads(path.read_text(encoding='utf-8'))
        for attempt in range(3):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'GundamReburnReference/1.0'})
                with urllib.request.urlopen(req, timeout=30) as response:
                    data = json.load(response)
                if 'error' in data:
                    raise RuntimeError(data['error'])
                path.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
                time.sleep(1.0)
                return data
            except (OSError, ValueError):
                if attempt == 2: raise
                time.sleep(2 * (attempt + 1))


def fetch_pages(client, titles):
    try:
        data = client.get(action='query', prop='revisions', rvprop='ids|timestamp|content',
                          rvslots='main', titles='|'.join(titles), redirects=1)
        return list(data['query']['pages'].values()), []
    except OSError as error:
        if len(titles) > 1:
            left, failed_left = fetch_pages(client, titles[:len(titles) // 2])
            right, failed_right = fetch_pages(client, titles[len(titles) // 2:])
            return left + right, failed_left + failed_right
        return [], [{'title': titles[0], 'error': str(error)}]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=Path('server/reference/wiki'))
    parser.add_argument('--max-pages', type=int, default=0, help='0 fetches all listed unit pages')
    args = parser.parse_args()
    client = WikiClient(args.out / 'raw')
    entries = {}
    for category in ('已更新机体', '待更新机体'):
        offset = 0
        while True:
            query = '[[分类:%s]]|' % category + '|'.join('?' + p for p in PROPERTIES)
            data = client.get(action='ask', query=query + '|limit=500|offset=%d' % offset)
            for title, item in data['query']['results'].items():
                entries[title] = dict(item, category=category)
            next_offset = data.get('query-continue-offset')
            if next_offset is None or int(next_offset) <= offset: break
            offset = int(next_offset)
    comparison = client.get(action='parse', page='敢达OL机体对比工具', prop='links')
    titles = sorted({link['*'] for link in comparison['parse']['links']
                     if link['ns'] == 0 and link['*'].startswith(('高达OL', '敢达OL'))
                     and link['*'] not in ('高达OL', '敢达OL机体对比工具') and 'exists' in link})
    if args.max_pages: titles = titles[:args.max_pages]
    units, failures = [], []
    for start in range(0, len(titles), 5):
        # Encoded Chinese titles can exceed proxy URL limits in larger batches.
        batch = titles[start:start + 5]
        pages, failed = fetch_pages(client, batch)
        failures.extend(failed)
        for page in pages:
            title = page['title']
            revisions = page.get('revisions') or []
            if not revisions:
                failures.append(title)
                continue
            rev = revisions[0]
            text = rev.get('slots', {}).get('main', {}).get('*', rev.get('*', ''))
            unit = parse_unit(title, 'https://wiki.biligame.com/gundam/' + urllib.parse.quote(title),
                              rev['revid'], text)
            units.append(enrich_unit(unit, entries))
        print('pages %d/%d; weapons=%d' % (min(start + 5, len(titles)), len(titles),
                                             sum(len(u['weapons']) for u in units)), flush=True)
    units = complete_catalog(units, entries)
    output = {'retrieved_at_utc': datetime.now(timezone.utc).isoformat(), 'source_api': API,
              'warning': 'Wiki balance/version and IDs are not verified for v5.0.0.33.',
              'catalog_count': len(entries), 'pages_requested': len(titles), 'failures': failures,
              'catalog': entries, 'units': units}
    (args.out / 'units.json').write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding='utf-8')
    print('saved', args.out / 'units.json', flush=True)


if __name__ == '__main__':
    main()
