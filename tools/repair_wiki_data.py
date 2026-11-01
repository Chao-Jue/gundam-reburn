"""Retry failed Wiki pages and retain category-only references. Never drop good records."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from urllib.parse import urlencode, quote

from playwright.sync_api import sync_playwright
from crawl_gundam_wiki import parse_unit, enrich_unit, complete_catalog


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data', type=Path, default=Path('server/reference/wiki/units.json'))
    args = parser.parse_args()
    original = args.data.read_bytes()
    data = json.loads(original)
    backup = args.data.with_name('units.before-repair-' + hashlib.sha256(original).hexdigest()[:12] + '.json')
    if not backup.exists(): backup.write_bytes(original)
    records = {u['title']: u for u in data['units']}
    failed = []
    with sync_playwright() as p:
        client = p.request.new_context()
        for entry in data.get('failures', []):
            title = entry['title'] if isinstance(entry, dict) else entry
            query = dict(action='query', format='json', prop='revisions', rvprop='ids|timestamp|content',
                         rvslots='main', redirects=1, titles=title)
            try:
                response = client.get('https://wiki.biligame.com/gundam/api.php?' + urlencode(query), timeout=25000)
                raw = response.json()
                raw_dir = args.data.parent / 'raw'
                raw_dir.mkdir(exist_ok=True)
                (raw_dir / ('repair-' + hashlib.sha256(title.encode()).hexdigest() + '.json')).write_text(
                    json.dumps(raw, ensure_ascii=False), 'utf8')
                pages = [v for v in raw.get('query', {}).get('pages', {}).values() if v.get('revisions')]
                if not pages: raise ValueError('No revision returned')
                for page in pages:
                    rev = page['revisions'][0]
                    unit = parse_unit(page['title'], 'https://wiki.biligame.com/gundam/' + quote(page['title']),
                                      rev['revid'], rev['slots']['main']['*'])
                    unit['aliases'] = [title] if page['title'] != title else []
                    unit['data_completeness'] = 'page_fetched'
                    records[unit['title']] = enrich_unit(unit, data['catalog'])
                print('Fetched', title.encode('unicode_escape').decode(), flush=True)
            except Exception as error:
                failed.append({'title': title, 'error': str(error)[:300]})
        client.dispose()
    data['units'] = complete_catalog(list(records.values()), data['catalog'])
    data['failures'] = failed
    data['repaired_at_utc'] = datetime.now(timezone.utc).isoformat()
    data['coverage'] = {'unique_records': len(data['units']),
                        'catalog_only': sum(u.get('data_completeness') == 'catalog_only' for u in data['units']),
                        'remaining_page_failures': len(failed)}
    temporary = args.data.with_suffix('.tmp')
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), 'utf8')
    temporary.replace(args.data)
    print(data['coverage'])


if __name__ == '__main__': main()
