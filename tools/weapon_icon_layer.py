"""L1 图标层：Wiki 图标名 → 客户端格纳库图标（+ 战场图标、反推模型）候选。

只生成候选，不写确认结果。归一化与描述子直接复用 `weapon_icon_match`，
保证和之前那版图标的判据是同一套（颜色 .45 / 边缘 .35 / alpha .2 的加权像素差）。

候选里带三个来源证据：
- `icon_similarity`：描述子距离（越低越像，不是概率）
- `name_key`：客户端图标文件名里的资源号是否恰好等于反推出的模型
- `battle`：同 key 的战场图标是否存在
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request

import numpy as np
from PIL import Image

import weapon_icon_match

API = 'https://wiki.biligame.com/gundam/api.php'
AGENT = 'gundam-reburn-local/1.0 (offline asset research)'
# weapon_icon_match.descriptor 的输出长度：32x16 的颜色 + 边缘 + alpha 三段
DESCRIPTOR_SIZE = 32 * 16 * 3 + 32 * 16 + 32 * 16


def _get(url, timeout=40, attempts=4):
    """带退避的 GET。bilibili 在并发高时返回 567/429，必须退避而不是当失败。"""
    last = None
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': AGENT})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            last = error
            if error.code in (429, 500, 502, 503, 504, 567):
                time.sleep(1.5 * (attempt + 1))
                continue
            raise
        except Exception as error:
            last = error
            time.sleep(1.0 * (attempt + 1))
    raise last


def wiki_urls(names, batch=10, timeout=40):
    """批量查文件 URL；返回 {图片名: url}。

    bilibili 的 api.php 对超长 titles 参数会直接失败（整批返回空/异常），
    所以批量小一点，失败就把这一批对半拆开重试；仍失败的计入 missing 而不是静默丢掉。
    """
    urls, failed = {}, []

    def query(chunk):
        titles = '|'.join('文件:%s.png' % n for n in chunk)
        params = urllib.parse.urlencode({'action': 'query', 'format': 'json',
                                         'prop': 'imageinfo', 'iiprop': 'url', 'titles': titles})
        data = json.loads(_get('%s?%s' % (API, params), timeout))
        pages = data.get('query', {}).get('pages', {})
        if not pages:
            raise ValueError('empty pages')
        for page in pages.values():
            info = (page.get('imageinfo') or [{}])[0]
            title = page.get('title', '')
            if not info.get('url') or ':' not in title:
                continue
            name = title.split(':', 1)[1]
            if name.lower().endswith('.png'):
                name = name[:-4]
            urls[name.replace('_', ' ')] = info['url']

    def run(chunk):
        try:
            query(chunk)
        except Exception:
            if len(chunk) == 1:
                failed.append(chunk[0])
                return
            middle = len(chunk) // 2
            run(chunk[:middle])
            run(chunk[middle:])

    names = list(names)
    for start in range(0, len(names), batch):
        run(names[start:start + batch])
        if start % (batch * 10) == 0:
            print('  URL 进度 %d/%d' % (min(start + batch, len(names)), len(names)), flush=True)
    wiki_urls.failed = failed
    return urls


def icon_key(name):
    return hashlib.sha1(name.encode('utf8')).hexdigest()[:16]


def fetch_icon(name, url, folder):
    """下载并按名字哈希缓存；已存在就不重复下。返回本地路径或 None。"""
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / icon_key(name)
    if path.exists() and path.stat().st_size > 0:
        return path
    if not url:
        return None
    try:
        raw = _get(url)
        Image.open(io.BytesIO(raw)).verify()
    except Exception:
        return None
    path.write_bytes(raw)
    return path


def descriptor_of(path):
    with Image.open(path) as image:
        return weapon_icon_match.descriptor(weapon_icon_match.normalize(image))


def model_from_icon(stem):
    """s02010601 → 02010601；不足 8 位或不是数字就返回 None。"""
    digits = stem[1:9]
    if len(digits) == 8 and digits.isdigit():
        return digits
    return None


def battle_from_hangar(stem):
    """s02010601 → b02010601：只把首字母 s 换成 b。

    注意区分：weapon_threeway 里用来配对两套图标的 key 是 `stem[3:]`，
    那只用于比较是否同一把武器；构造文件名必须保留完整数字段。
    """
    if not stem.startswith('s') or len(stem) < 4:
        return None
    return 'b' + stem[1:]


def client_index(assets, cache=None, subfolder='interface/icon/item/s', size=(32, 16)):
    """索引 interface/icon/item/s/*.dds；带缓存，避免每次重算 5000 张图。

    缓存签名用「文件名单哈希」而不是逐个比较：过滤后的名单本来就短于文件列表，
    直接比列表会永远不命中。
    """
    folder = Path(assets) / subfolder
    files = sorted(folder.glob('*.dds'))
    signature = hashlib.sha1('|'.join(f.name for f in files).encode()).hexdigest()
    if cache and Path(cache).exists():
        data = np.load(cache, allow_pickle=True)
        if str(data['signature']) == signature:
            return [{'name': str(n), 'vector': v} for n, v in zip(data['paths'], data['vectors'])]
    vectors, names, errors = [], [], []
    for path in files:
        try:
            with Image.open(path) as image:
                if image.width / image.height < 1.5:
                    continue
                vector = weapon_icon_match.descriptor(weapon_icon_match.normalize(image))
        except Exception as error:
            errors.append({'file': path.name, 'error': str(error)[:80]})
            continue
        names.append(path.name)
        vectors.append(vector)
    matrix = np.stack(vectors) if vectors else np.zeros((0, DESCRIPTOR_SIZE), np.float32)
    if cache:
        Path(cache).parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(cache, signature=np.array(signature), paths=np.array(names),
                            vectors=matrix.astype(np.float32))
    return [{'name': n, 'vector': v} for n, v in zip(names, matrix)]


def match_icons(names, assets, icon_folder, cache=None, top=6, battle_top=4):
    """对每个 Wiki 图标名给出客户端候选。

    返回 ({name: {'candidates': [...], 'battle_candidates': [...]}}, stats)。
    仓图标按描述子排序；战图标独立排序（不能靠同号推——实测只命中 83 个仓图标）。
    """
    folder = Path(icon_folder)
    folder.mkdir(parents=True, exist_ok=True)
    # 已经下过的不用再查 URL，省掉整轮 API 请求
    pending = [n for n in names
               if not (folder / icon_key(n)).exists() or (folder / icon_key(n)).stat().st_size == 0]
    urls = wiki_urls(pending) if pending else {}
    hangar = client_index(assets, cache)
    battle_index = client_index(assets, Path(str(cache)).with_name('battle_icons.npz'),
                                'interface/icon/battle/b')
    if not hangar:
        return {}, {'urls': len(urls), 'downloaded': 0, 'missing': list(names)}
    matrix = np.stack([item['vector'] for item in hangar])
    stems = [Path(item['name']).stem for item in hangar]
    battle_matrix = np.stack([item['vector'] for item in battle_index]) if battle_index else None
    battle_names = [item['name'] for item in battle_index]
    # 并发太高会被限流（HTTP 567）；2 路 + 轻微间隔更稳
    def download(name):
        result = fetch_icon(name, urls.get(name), folder)
        time.sleep(0.12)
        return result

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(download, names))
    result, missing = {}, []
    downloaded = 0
    for name in names:
        path = folder / icon_key(name)
        if not path.exists() or path.stat().st_size == 0:
            missing.append(name)
            continue
        downloaded += 1
        try:
            vector = descriptor_of(path)
        except Exception:
            missing.append(name)
            continue
        distance = np.mean(np.abs(matrix - vector), axis=1)
        candidates = []
        for i in np.argsort(distance)[:top]:
            stem = stems[i]
            same_number = battle_from_hangar(stem)
            battle_path = Path(assets) / 'interface/icon/battle/b' / (same_number + '.dds')
            candidates.append({
                'hangar': 'interface/icon/item/s/' + hangar[i]['name'],
                'battle': ('interface/icon/battle/b/%s.dds' % same_number)
                          if same_number and battle_path.is_file() else None,
                'score': round(float(distance[i]), 6),
                'model': model_from_icon(stem),
                'name_key': stem,
            })
        battle_candidates = []
        if battle_matrix is not None:
            battle_distance = np.mean(np.abs(battle_matrix - vector), axis=1)
            for i in np.argsort(battle_distance)[:battle_top]:
                battle_candidates.append({
                    'battle': 'interface/icon/battle/b/' + battle_names[i],
                    'score': round(float(battle_distance[i]), 6),
                    'name_key': Path(battle_names[i]).stem,
                })
        result[name] = {'candidates': candidates, 'battle_candidates': battle_candidates}
    return result, {'urls': len(urls), 'downloaded': downloaded, 'missing': missing}
