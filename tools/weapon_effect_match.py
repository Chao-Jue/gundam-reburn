"""武器特效匹配工作站（本机 127.0.0.1，只读资源 + 只写自己的复核 JSON）。

流程：选武器 → 按分类浏览特效库 → 看「武器模型 + 该特效」的组合预览 →
按槽位（枪口/弹体/命中/刀刃/挂载）人工指派 → 导出 JSON。

不做的事：不写服务端武器定义、不改客户端资源、不自动把候选当结论。
"""
import argparse
from datetime import datetime, timezone
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import re
import threading
from urllib.parse import urlparse, parse_qs
import webbrowser

from PIL import Image

import effect_lib
import effect_render

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'GundamOnline_CHINA_已解密/decrypted'
OUT = ROOT / 'server/reference/weapon_effect_match'
SAVE = OUT / 'weapon_effect_assignments.json'
PAGE = Path(__file__).with_suffix('.html')
LOCK = threading.RLock()

CATEGORIES = [
    ('all', '全部'),
    ('muzzle', '枪口/发射'),
    ('blade', '刀刃'),
    ('beam', '光束'),
    ('explosion', '爆炸/命中'),
    ('smoke', '烟雾'),
    ('spark', '火花/电'),
    ('trail', '轨迹'),
    ('aura', '光效/光环'),
    ('thruster', '推进器'),
    ('shield', '盾'),
    ('attached', '有挂点'),
    ('ui', 'UI/场景'),
    ('other', '其他'),
]

SLOTS = ['muzzle', 'projectile', 'impact', 'blade', 'attached']


# ------------------------------------------------------------------ 索引
def effect_index():
    """fx/ 下所有 VRA 的结构摘要；解析失败就记下来，不跳过。

    fx/NN/attr/ 下的是被别的特效引用的模型/材质描述（PZ_*），不能单独播放，
    所以不进浏览列表，只统计条数。
    """
    items, failures = [], []
    attr_only = 0
    for path in sorted((ASSETS / 'fx').rglob('*.vra')):
        relative = path.relative_to(ASSETS).as_posix()
        if '/attr/' in relative:
            attr_only += 1
            continue
        try:
            effect = effect_lib.load(path)
        except Exception as error:
            failures.append({'path': relative, 'error': str(error)[:120]})
            continue
        items.append({
            'path': relative,
            'name': path.stem,
            'primary': effect.primary,
            'tags': effect.tags,
            'frame': effect.frame,
            'loop': effect.loop,
            'owner': effect.target['owner'],
            'kinds': effect.kinds,
            'plugs': len(effect.plugs),
            'textures': effect.textures[:2],
            't': round(effect.best_ratio(), 2),
            'signature': effect_lib.signature_text(effect),
        })
    return items, failures, attr_only


WEAPON_PATH = re.compile(r'item/(\d{2})/(\d{4})/model/EM_\d{2}_\d{4}_(\d{2})\.dxg$')


def weapon_index():
    weapons, failures = [], []
    for path in sorted((ASSETS / 'item').rglob('EM_*.dxg')):
        relative = path.relative_to(ASSETS).as_posix()
        match = WEAPON_PATH.search(relative)
        if not match:
            continue
        a, b, c = match.groups()
        try:
            model = effect_render.load_model(path)
        except Exception as error:
            failures.append({'path': relative, 'error': str(error)[:120]})
            continue
        weapons.append({
            'path': relative,
            'resource': int(a) * 1000000 + int(b) * 100 + int(c),
            'mesh': ','.join(m['name'] for m in model['meshes'])[:120],
            'sockets': [s['name'] for s in model['sockets']],
            'version': model.get('version', '?'),
        })
    return weapons, failures


def known_names():
    names = {}
    for file in ('gm_starter_weapons.json', 'gm_test_weapons.json'):
        path = ROOT / 'server/reference' / file
        if not path.exists():
            continue
        for weapon in json.loads(path.read_text('utf8')).get('weapons', []):
            if weapon.get('resource'):
                names.setdefault(int(weapon['resource']), weapon.get('name') or '')
    return names


# ------------------------------------------------------------------ 预览
@lru_cache(maxsize=400)
def preview(weapon_path, effect_path, ratio, width, height):
    try:
        effect = effect_lib.load(ASSETS / effect_path)
        image, meta = effect_render.compose(ASSETS, ASSETS / weapon_path, effect, ratio,
                                            size=(width, height))
    except Exception as error:
        # 单个特效画不出来不能让整页出现破图：返回占位图并把原因写进 meta
        image = Image.new('RGB', (width, height), (28, 34, 44))
        meta = {'error': '%s: %s' % (type(error).__name__, str(error)[:160])}
    buffer = io.BytesIO()
    image.convert('RGB').save(buffer, 'PNG')
    return buffer.getvalue(), meta


def read_saved():
    if SAVE.exists():
        return json.loads(SAVE.read_text('utf8'))
    return {'schema_version': 1, 'note': '人工指派的特效候选；不自动写服务端武器定义',
            'assignments': {}}


def write_saved(data):
    with LOCK:
        SAVE.parent.mkdir(parents=True, exist_ok=True)
        temporary = SAVE.with_suffix('.tmp')
        temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), 'utf8')
        temporary.replace(SAVE)


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
            if request.path == '/api/index':
                counts = {'all': len(EFFECTS)}
                for item in EFFECTS:
                    for tag in item['tags']:
                        counts[tag] = counts.get(tag, 0) + 1
                return self.reply({
                    'effects': EFFECTS,
                    'weapons': WEAPONS,
                    'categories': [{'key': k, 'label': v, 'count': counts.get(k, 0)}
                                   for k, v in CATEGORIES if k == 'all' or counts.get(k)],
                    'slots': SLOTS,
                    'saved': read_saved(),
                    'failures': {'effects': EFFECT_FAILURES, 'weapons': WEAPON_FAILURES},
                    'attr_only': ATTR_ONLY,
                    'save_path': str(SAVE.relative_to(ROOT)).replace('\\', '/'),
                })
            if request.path == '/api/preview':
                weapon = query.get('weapon', [''])[0]
                effect = query.get('effect', [''])[0]
                ratio = min(1.0, max(0.0, float(query.get('t', ['0.3'])[0])))
                width = int(query.get('w', ['520'])[0])
                height = int(query.get('h', ['320'])[0])
                if weapon not in WEAPON_MAP or effect not in EFFECT_MAP:
                    raise ValueError('武器或特效不在索引里')
                if not 120 <= width <= 1200 or not 80 <= height <= 800:
                    raise ValueError('预览尺寸越界')
                image, meta = preview(weapon, effect, round(ratio, 2), width, height)
                self.send_response(200)
                self.send_header('Content-Type', 'image/png')
                self.send_header('Content-Length', str(len(image)))
                self.send_header('X-Preview-Meta', json.dumps(meta, ensure_ascii=False)[:1800]
                                 .encode('unicode_escape').decode('ascii'))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(image)
                return
            if request.path == '/api/export':
                return self.reply(read_saved())
            path = PAGE if request.path in ('/', '/index.html') else None
            if path is None:
                return self.reply({'error': 'not found'}, 404)
            return self.reply(path.read_bytes(), content_type='text/html; charset=utf-8')
        except Exception as error:
            self.reply({'error': str(error)}, 400)

    def do_POST(self):
        try:
            if self.path != '/api/assign':
                return self.reply({'error': 'not found'}, 404)
            origin = self.headers.get('Origin')
            if origin and origin != 'http://' + self.headers.get('Host', ''):
                raise ValueError('不接受跨站写入')
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length < 20000:
                raise ValueError('请求长度无效')
            body = json.loads(self.rfile.read(length))
            weapon = body.get('weapon', '')
            if weapon not in WEAPON_MAP:
                raise ValueError('武器不在索引里')
            data = read_saved()
            record = data['assignments'].setdefault(weapon, {
                'resource': WEAPON_MAP[weapon]['resource'],
                'mesh': WEAPON_MAP[weapon]['mesh'], 'slots': {}})
            for slot in body.get('slots', {}).items():
                name, effect = slot
                if name not in SLOTS:
                    raise ValueError('未知槽位: %s' % name)
                if effect and effect not in EFFECT_MAP:
                    raise ValueError('特效不在索引里: %s' % effect)
                if effect:
                    record['slots'][name] = effect
                else:
                    record['slots'].pop(name, None)
            if body.get('clear'):
                data['assignments'].pop(weapon, None)
            else:
                record['updated_at'] = datetime.now(timezone.utc).isoformat()
            write_saved(data)
            self.reply(data)
        except Exception as error:
            self.reply({'error': str(error)}, 400)


def main():
    global EFFECTS, WEAPONS, EFFECT_MAP, WEAPON_MAP, EFFECT_FAILURES, WEAPON_FAILURES, ATTR_ONLY
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8769)
    parser.add_argument('--assets', type=Path, default=ASSETS)
    parser.add_argument('--save', type=Path, default=SAVE)
    parser.add_argument('--open', action='store_true')
    parser.add_argument('--index-only', action='store_true', help='只生成索引 JSON，不启动服务')
    args = parser.parse_args()

    globals()['ASSETS'] = args.assets.resolve()
    globals()['SAVE'] = args.save.resolve()

    print('扫描特效库...', flush=True)
    EFFECTS, EFFECT_FAILURES, ATTR_ONLY = effect_index()
    print('扫描武器外观...', flush=True)
    WEAPONS, WEAPON_FAILURES = weapon_index()
    names = known_names()
    for weapon in WEAPONS:
        weapon['name'] = names.get(weapon['resource'], '')
    EFFECT_MAP = {item['path']: item for item in EFFECTS}
    WEAPON_MAP = {item['path']: item for item in WEAPONS}
    print('特效 %d（失败 %d，另跳过 attr 子资源 %d），武器 %d（失败 %d）'
          % (len(EFFECTS), len(EFFECT_FAILURES), ATTR_ONLY,
             len(WEAPONS), len(WEAPON_FAILURES)), flush=True)

    if args.index_only:
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / 'effect_index.json').write_text(json.dumps({
            'schema_version': 1, 'assets': str(globals()['ASSETS']),
            'effects': EFFECTS, 'weapons': WEAPONS,
            'failures': {'effects': EFFECT_FAILURES, 'weapons': WEAPON_FAILURES},
            'attr_only': ATTR_ONLY,
            'method': 'VRA 结构解析 + 插件名关键词分类；预览为离线近似合成，不是渲染验收',
        }, ensure_ascii=False, indent=1), 'utf8')
        print('写出', OUT / 'effect_index.json', flush=True)
        return

    print('http://127.0.0.1:%d' % args.port, flush=True)
    print('人工指派写入', globals()['SAVE'], flush=True)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    if args.open:
        threading.Timer(0.6, lambda: webbrowser.open('http://127.0.0.1:%d' % args.port)).start()
    server.serve_forever()


if __name__ == '__main__':
    main()
