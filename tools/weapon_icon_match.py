"""Download Wiki weapon icons and generate reviewable, non-authoritative candidates.

Requires Pillow, numpy, playwright. Never writes server weapon definitions.
"""
import argparse
from collections import deque
import hashlib
import html
import io
import json
from pathlib import Path
from urllib.parse import urlencode

import numpy as np
from PIL import Image, ImageFilter
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]


def references(units, unit_filter=''):
    refs = {}
    for unit in units:
        if unit_filter and unit_filter not in unit['title']: continue
        previous = None
        for number, weapon in enumerate(unit['weapons']):
            fields = weapon['attributes']
            explicit = next(((k, v) for k, v in fields.items() if '图片名称' in k and v.strip()), None)
            if explicit:
                key, name = explicit
                ext = '.jpg' if 'jpg' in key.lower() else '.png'
                previous = name if name.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')) else name + ext
            # Insert-row templates render under the preceding weapon icon.
            elif '插入行' not in weapon.get('template', ''):
                previous = None
            if previous:
                refs.setdefault(previous, []).append({'unit': unit['title'], 'weapon': weapon['name'],
                    'weapon_index': number, 'source_url': unit['source_url'], 'inherited': explicit is None})
    return refs


def normalize(image):
    """Remove only edge-connected near-background pixels; preserve interior colors."""
    rgba = np.array(image.convert('RGBA'))
    h, w = rgba.shape[:2]
    if rgba[:, :, 3].min() == 255:
        colors = rgba[:, :, :3].astype(np.int16)
        corners = colors[[0, 0, h-1, h-1], [0, w-1, 0, w-1]]
        background = np.median(corners, axis=0)
        allowed = np.max(abs(colors - background), axis=2) <= 24
        # The Wiki screenshots often keep the client's striped blue UI panel.
        # Enable its chroma mask only when it dominates the outer boundary;
        # still flood from the boundary, never globally erase blue components.
        blue = ((colors[:,:,2] > colors[:,:,0]*1.3) &
                (colors[:,:,1] > colors[:,:,0]*1.1) &
                (colors[:,:,2] > colors[:,:,1]*1.1) & (colors[:,:,2] > 35))
        border = np.zeros((h,w), dtype=bool)
        border[0,:]=border[-1,:]=True; border[:,0]=border[:,-1]=True
        if blue[border].mean() > .35:
            allowed |= blue
        visited = np.zeros((h, w), dtype=bool)
        queue = deque((y, x) for y in range(h) for x in range(w)
                      if (y in (0, h-1) or x in (0, w-1)) and allowed[y, x])
        while queue:
            y, x = queue.popleft()
            if visited[y, x]: continue
            visited[y, x] = True
            for ny, nx in ((y-1,x),(y+1,x),(y,x-1),(y,x+1)):
                if 0 <= ny < h and 0 <= nx < w and allowed[ny,nx] and not visited[ny,nx]:
                    queue.append((ny,nx))
        rgba[visited, 3] = 0
    cut = Image.fromarray(rgba)
    box = cut.getchannel('A').getbbox()
    if not box: raise ValueError('empty icon')
    cut = cut.crop(box)
    cut.thumbnail((92, 44), Image.Resampling.LANCZOS)
    canvas = Image.new('RGBA', (96, 48))
    canvas.alpha_composite(cut, ((96-cut.width)//2, (48-cut.height)//2))
    return canvas


def descriptor(image):
    background = Image.new('RGBA', image.size, (30,30,30,255))
    background.alpha_composite(image)
    small = background.convert('RGB').resize((32,16), Image.Resampling.LANCZOS)
    color = np.asarray(small, dtype=np.float32).reshape(-1)/255
    edge = np.asarray(small.convert('L').filter(ImageFilter.FIND_EDGES), dtype=np.float32).reshape(-1)/255
    alpha = np.asarray(image.getchannel('A').resize((32,16)), dtype=np.float32).reshape(-1)/255
    return np.concatenate((color*.45, edge*.35, alpha*.2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--unit', default='', help='Wiki title substring; empty processes all template weapons')
    parser.add_argument('--assets', type=Path, default=ROOT/'GundamOnline_CHINA_已解密/decrypted')
    parser.add_argument('--out', type=Path, default=ROOT/'server/reference/weapon_icon_match')
    args = parser.parse_args()
    for sub in ['original', 'normalized', 'client']: (args.out/sub).mkdir(parents=True, exist_ok=True)
    refs = references(json.loads((ROOT/'server/reference/wiki/units.json').read_text('utf8'))['units'], args.unit)
    sources, failures = {}, []
    with sync_playwright() as p:
        request = p.request.new_context()
        names = list(refs)
        for start in range(0,len(names),8):
            batch = names[start:start+8]
            params = dict(action='query',format='json',prop='imageinfo',iiprop='url',titles='|'.join('文件:'+n for n in batch))
            try:
                r = request.get('https://wiki.biligame.com/gundam/api.php?'+urlencode(params),timeout=25000)
                for page in r.json().get('query',{}).get('pages',{}).values():
                    info = page.get('imageinfo',[{}])[0]
                    if info.get('url'): sources[page['title'].split(':',1)[1].replace('_',' ')] = info['url']
            except Exception as e: failures.append({'batch':batch,'error':str(e)[:200]})
        icons = []
        for name, uses in refs.items():
            url = sources.get(name.replace('_',' '))
            if not url:
                failures.append({'name':name,'error':'image URL unavailable'});continue
            key = hashlib.sha256(name.encode()).hexdigest()[:20]
            original = args.out/'original'/key
            try:
                if not original.exists():
                    r = request.get(url,timeout=25000)
                    if not r.ok: raise ValueError('image HTTP '+str(r.status))
                    raw = r.body()
                    Image.open(io.BytesIO(raw)).verify()
                    original.write_bytes(raw)
                with Image.open(original) as im: image = normalize(im)
                image.save(args.out/'normalized'/f'{key}.png')
                icons.append({'key':key,'wiki_image':name,'url':url,'uses':uses,'vector':descriptor(image)})
            except Exception as e: failures.append({'name':name,'error':str(e)[:200]})
        request.dispose()
    paths, vectors, errors = [], [], []
    for file in sorted((args.assets/'interface/icon/item').rglob('*.dds')):
        try:
            with Image.open(file) as im:
                if im.width/im.height < 1.5: continue
                image = normalize(im)
            paths.append(file)
            vectors.append(descriptor(image))
        except Exception as e: errors.append({'path':str(file.relative_to(args.assets)),'error':str(e)[:150]})
    if not vectors: raise RuntimeError('No client item icons found')
    matrix = np.stack(vectors)
    results = []
    for icon in icons:
        distance = np.mean(abs(matrix-icon.pop('vector')),axis=1)
        ranking = np.argsort(distance)[:5]
        candidates=[]
        for index in ranking:
            file=paths[index]; relative=file.relative_to(args.assets).as_posix()
            key=hashlib.sha256(relative.encode()).hexdigest()[:20]
            with Image.open(file) as im:normalize(im).save(args.out/'client'/f'{key}.png')
            candidates.append({'path':relative,'preview':f'client/{key}.png','distance':float(distance[index])})
        results.append(dict(icon,candidates=candidates,status='unreviewed'))
    report={'method':'normalized RGB + edge + alpha weighted MAE; lower is closer; not probability',
            'client_icons':len(paths),'failures':failures,'client_decode_errors':errors,'results':results}
    (args.out/'candidates.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf8')
    cards=[]
    for icon in results:
        title=html.escape(icon['wiki_image']); uses=html.escape(' / '.join(dict.fromkeys(u['weapon'] for u in icon['uses'])))
        options=''.join(f'<label><input type="radio" name="{icon["key"]}" value="{html.escape(c["path"],quote=True)}"><img src="{c["preview"]}"><small>{c["distance"]:.5f}<br>{html.escape(c["path"])}</small></label>' for c in icon['candidates'])
        cards.append(f'<section><h3>{title}</h3><p>{uses}</p><img src="normalized/{icon["key"]}.png"><div class="choices">{options}<label><input type="radio" name="{icon["key"]}" value="">均不匹配</label></div></section>')
    document='''<!doctype html><meta charset="utf-8"><title>武器图标候选复核</title><style>body{background:#111c29;color:#eee;font:14px sans-serif;padding:20px}section{border:1px solid #456;padding:15px;margin:15px 0}.choices{display:flex;gap:20px}label{display:flex;flex-direction:column;max-width:210px}img{width:144px;height:72px;object-fit:contain;background:#384555}small{word-break:break-all}button{padding:12px;position:sticky;top:0}</style><button id="export">导出人工选择</button><p>距离越低越相似，不是置信概率。候选不会自动转成游戏武器ID；未勾选保持未确认。保存导出的JSON供后续导入。</p>'''+''.join(cards)+'''<script>document.querySelector('#export').onclick=()=>{const matches={};for(const e of document.querySelectorAll('input:checked'))matches[e.name]=e.value;const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify({schema_version:1,matches},null,2)],{type:'application/json'}));a.download='weapon_icon_review.json';a.click();};</script>'''
    (args.out/'review.html').write_text(document,'utf8')
    print(f'Wiki icons {len(results)}/{len(refs)}, client icons {len(paths)}, failures {len(failures)}; {args.out}/review.html')


if __name__=='__main__':main()
