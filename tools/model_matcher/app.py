"""Local-only model / Wiki matching workstation. Run with Python, no elevation."""
import argparse
from datetime import datetime, timezone
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import hashlib
import json
from pathlib import Path
import re
import threading
from urllib.parse import urlparse, parse_qs

from PIL import Image
from dxg import parse

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / 'GundamOnline_CHINA_已解密/decrypted'
SAVE = ROOT / 'server/reference/model_matches.json'
WEB = Path(__file__).parent / 'web'
LOCK = threading.RLock()


def catalog():
    result = []
    for p in sorted((ASSETS / 'chara').rglob('MSM_*.dxg')):
        match = re.fullmatch(r'MSM_(\d{2})(\d{2})_(\d{4})_(\d{2})', p.stem)
        if not match: continue
        a, b, c, d = map(int, match.groups())
        result.append({'key': p.relative_to(ASSETS).as_posix(),
                       'model_id': (a * 100 + b) * 1000000 + c * 100 + d,
                       'label': p.stem, 'group': f'{a:02}/{b:02}/{c:04}'})
    return result


def read_matches():
    return json.loads(SAVE.read_text('utf8')) if SAVE.exists() else {'schema_version': 1, 'matches': {}}


def save_match(key, value):
    # One model may match multiple data variants (gold/silver or named variants).
    with LOCK:
        data = read_matches()
        if value is None: data['matches'].pop(key, None)
        else: data['matches'][key] = value
        SAVE.parent.mkdir(parents=True, exist_ok=True)
        temporary = SAVE.with_suffix('.tmp')
        temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), 'utf8')
        temporary.replace(SAVE)
    return data


@lru_cache(maxsize=12)
def model_data(key):
    return parse((ASSETS / key).read_bytes())


class Handler(BaseHTTPRequestHandler):
    def reply(self, value, status=200, content_type='application/json; charset=utf-8'):
        if not isinstance(value, bytes): value = json.dumps(value, ensure_ascii=False).encode()
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
            key = query.get('key', [''])[0]
            if request.path == '/api/catalog':
                return self.reply({'models': MODELS, 'units': UNITS,
                                   'saved': read_matches(), 'save_path': str(SAVE)})
            if request.path == '/api/export': return self.reply(read_matches())
            if request.path == '/api/model':
                if key not in MODEL_MAP: raise ValueError('模型不存在')
                data = dict(model_data(key))
                folder = (ASSETS / key).parent.parent / 'tex'
                data['textures'] = [p.relative_to(ASSETS).as_posix() for p in sorted(folder.glob('*.dds'))]
                return self.reply(data)
            if request.path == '/api/texture':
                p = (ASSETS / key).resolve()
                if not p.is_relative_to(ASSETS.resolve()) or p.suffix.lower() != '.dds':
                    raise ValueError('贴图路径无效')
                with Image.open(p) as im:
                    im.thumbnail((2048, 2048))
                    output = io.BytesIO()
                    im.convert('RGBA').save(output, 'PNG')
                return self.reply(output.getvalue(), content_type='image/png')
            path = (WEB / (request.path.lstrip('/') or 'index.html')).resolve()
            if not path.is_relative_to(WEB.resolve()) or not path.is_file():
                return self.reply({'error': 'not found'}, 404)
            types = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css'}
            return self.reply(path.read_bytes(), content_type=types.get(path.suffix, 'application/octet-stream'))
        except Exception as error:
            self.reply({'error': str(error)}, 400)

    def do_POST(self):
        try:
            if self.path != '/api/match': return self.reply({'error': 'not found'}, 404)
            # Reject browser requests originating from an unrelated site.
            origin = self.headers.get('Origin')
            if origin and origin != 'http://' + self.headers.get('Host', ''):
                raise ValueError('不接受跨站写入')
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length < 100000: raise ValueError('请求长度无效')
            body = json.loads(self.rfile.read(length))
            key = body['key']
            if key not in MODEL_MAP: raise ValueError('模型不存在')
            if body.get('delete'):
                return self.reply(save_match(key, None))
            titles = body.get('titles', [])
            if not titles or any(t not in UNIT_MAP for t in titles): raise ValueError('请选择有效的数据条目')
            textures = body.get('textures', {})
            mesh_names = {m['name'] for m in model_data(key)['meshes']}
            folder = (ASSETS / key).parent.parent / 'tex'
            allowed = {p.relative_to(ASSETS).as_posix() for p in folder.glob('*.dds')}
            if any(n not in mesh_names or t not in allowed for n, t in textures.items()):
                raise ValueError('网格贴图映射无效')
            value = {'model_id': MODEL_MAP[key]['model_id'], 'model_path': key,
                     'model_sha256': hashlib.sha256((ASSETS / key).read_bytes()).hexdigest(),
                     'reference_asset_version': True,
                     'units': [{'title': t, 'revision_id': UNIT_MAP[t].get('revision_id'),
                                'source_url': UNIT_MAP[t].get('source_url')} for t in dict.fromkeys(titles)],
                     'textures': textures, 'texture_flip_y': bool(body.get('texture_flip_y', False)),
                     'hidden_meshes': [n for n in body.get('hidden_meshes', []) if n in mesh_names],
                     'notes': str(body.get('notes', ''))[:4000],
                     'status': 'manually_confirmed', 'updated_at_utc': datetime.now(timezone.utc).isoformat()}
            self.reply(save_match(key, value))
        except Exception as error:
            self.reply({'error': str(error)}, 400)


def main():
    global MODELS, MODEL_MAP, UNITS, UNIT_MAP, SAVE
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--save', type=Path, default=SAVE)
    parser.add_argument('--open', action='store_true', help='Open the local UI in the default browser')
    args = parser.parse_args()
    SAVE = args.save.resolve()
    MODELS = catalog()
    MODEL_MAP = {m['key']: m for m in MODELS}
    UNITS = json.loads((ROOT / 'server/reference/wiki/units.json').read_text('utf8'))['units']
    images_file = ROOT / 'server/reference/wiki/unit_images.json'
    images = json.loads(images_file.read_text('utf8')).get('images', {}) if images_file.exists() else {}
    for unit in UNITS:
        unit['portrait'] = images.get(unit['title'])
    UNIT_MAP = {u['title']: u for u in UNITS}
    print(f'http://127.0.0.1:{args.port}  models={len(MODELS)} units={len(UNITS)}', flush=True)
    print(f'Save: {SAVE}', flush=True)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    if args.open:
        import webbrowser
        threading.Timer(.5, lambda: webbrowser.open(f'http://127.0.0.1:{args.port}')).start()
    server.serve_forever()


if __name__ == '__main__': main()
