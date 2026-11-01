"""Resolve unit portraits from the Wiki's actual basic-stat template naming rule."""
import json
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'server/reference/wiki/unit_images.json'


def image_name(unit):
    name = unit.get('stats', {}).get('名称')
    if not name: return None
    return 'File:敢达OL' + name + '.png'


def main():
    # Browser network context avoids urllib requests rejected by this Wiki.
    from playwright.sync_api import sync_playwright
    units = json.loads((ROOT / 'server/reference/wiki/units.json').read_text('utf8'))['units']
    images = json.loads(OUT.read_text('utf8')).get('images', {}) if OUT.exists() else {}
    pending = [u for u in units if u['title'] not in images and image_name(u)]
    with sync_playwright() as p:
        request = p.request.new_context()
        for i in range(0, len(pending), 8):
            batch = pending[i:i+8]
            params = {'action': 'query', 'format': 'json', 'prop': 'imageinfo', 'iiprop': 'url',
                      'titles': '|'.join(image_name(u).replace('File:', '文件:', 1) for u in batch)}
            try:
                response = request.get('https://wiki.biligame.com/gundam/api.php?' + urlencode(params), timeout=20000)
                files = {}
                for page in response.json().get('query', {}).get('pages', {}).values():
                    info = page.get('imageinfo', [{}])[0]
                    if info.get('url'):
                        files[page['title'].split(':', 1)[1].replace('_', ' ')] = {
                            'url': info['url'], 'original_url': info['url'], 'file_title': page['title']}
                for unit in batch:
                    match = files.get(image_name(unit).split(':', 1)[1].replace('_', ' '))
                    if match: images[unit['title']] = match
            except Exception:
                pass
        request.dispose()
    OUT.write_text(json.dumps({'source': 'MediaWiki imageinfo; Template:高达OL基础性能',
                               'images': images, 'missing_titles': [u['title'] for u in units if u['title'] not in images]},
                              ensure_ascii=False, indent=2), 'utf8')
    print(f'Resolved {len(images)}/{len(units)} unit portraits: {OUT}', flush=True)


if __name__ == '__main__': main()
