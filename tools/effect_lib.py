"""VRA 特效资源解析与分类（只读，不渲染）。

VRA 是 CP932 编码的文本树，形如：

    {Plug
        (name string[1] "Flash")
        (start float[1] 0.000000)
        {Object
            {Sprite
                (file string[1] "fx/image/PT_01_100_01.png")
                (dims vector2[1] 40.000000, 40.000000)
            }
        }
        {Work
            {Color
                (ratio float[3] 0.0, 0.25, 1.0)
                (color vector4[3] 1,1,1,1, 1,1,1,1, 0,0,0,1)
            }
        }
    }

{...} 是块，(...) 是带类型的值；数组值用逗号分隔、可跨行。
这里只做结构化读取，任何字段缺失都返回 None，不猜默认语义。
"""
import re
from pathlib import Path

VALUE = re.compile(r'^\((\w+)\s+(\w+)(?:\[(\d+)\])?\s*(.*)\)$', re.S)


def parse_tree(text):
    """把 VRA 文本解析成 [{tag, values, children}]；值按类型转成 list。"""
    root = {'tag': '', 'values': {}, 'children': []}
    stack = [root]
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '{':
            j = i + 1
            while j < n and text[j] not in ' \t\r\n(':
                j += 1
            node = {'tag': text[i + 1:j], 'values': {}, 'children': []}
            stack[-1]['children'].append(node)
            stack.append(node)
            i = j
        elif ch == '}':
            if len(stack) > 1:
                stack.pop()
            i += 1
        elif ch == '(':
            depth, j = 0, i
            in_string = False
            while j < n:
                c = text[j]
                if c == '"':
                    in_string = not in_string
                elif not in_string and c == '(':
                    depth += 1
                elif not in_string and c == ')':
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            body = text[i:j + 1]
            match = VALUE.match(body)
            if match:
                key, kind, count, raw = match.groups()
                stack[-1]['values'][key] = _convert(kind, raw)
            i = j + 1
        else:
            i += 1
    return root['children']


def _convert(kind, raw):
    raw = raw.strip()
    if kind == 'string':
        found = re.match(r'"([^"]*)"', raw)
        return found.group(1) if found else raw
    numbers = re.findall(r'-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?', raw)
    if not numbers:
        return []
    return [float(x) if ('.' in x or 'e' in x.lower()) else int(x) for x in numbers]


def _first(node, tag):
    for child in node['children']:
        if child['tag'] == tag:
            return child
    return None


def _all(node, tag):
    return [c for c in node['children'] if c['tag'] == tag]


def _num(node, key, default=0.0):
    value = node['values'].get(key)
    if isinstance(value, list) and value:
        return float(value[0])
    return default


def _walk_value_files(node, found):
    """收集所有长得像资源路径的字符串。

    贴图在 (file ...) 里，模型却在 {attribute (Geometry ...)} 里，
    所以不能只认 file 这个键；没有斜杠的短名字（如 mtrl_name）不算路径。
    """
    for value in node['values'].values():
        items = value if isinstance(value, list) else [value]
        for item in items:
            if not isinstance(item, str) or len(item) < 4:
                continue
            if '/' in item or '\\' in item:
                found.append(item.replace('\\', '/'))
    for child in node['children']:
        _walk_value_files(child, found)


def _object_kind(obj):
    for child in obj['children']:
        if child['tag'] in ('Sprite', 'Particle', 'Model', 'Trail'):
            return child
    return None


def _work(plug, tag):
    work = _first(plug, 'Work')
    return _first(work, tag) if work else None


def _curve(node):
    """读完一条关键帧曲线：ratio 是时间轴，其它键是并列的值数组。"""
    if node is None:
        return None
    ratio = node['values'].get('ratio')
    if not isinstance(ratio, list) or not ratio:
        return None
    ratio = [float(x) for x in ratio]
    keys = {}
    for key, value in node['values'].items():
        if key == 'ratio' or not isinstance(value, list):
            continue
        per = len(value) // len(ratio)
        if per <= 0:
            continue
        keys[key] = [[float(x) for x in value[i * per:(i + 1) * per]] for i in range(len(ratio))]
    return {'ratio': ratio, 'keys': keys}


def sample(curve, ratio, key, default):
    """在曲线上按 0..1 取一个值，线性插值；超出范围用端点。"""
    if not curve or key not in curve['keys']:
        return list(default)
    times = curve['ratio']
    values = curve['keys'][key]
    if ratio <= times[0]:
        return list(values[0])
    if ratio >= times[-1]:
        return list(values[-1])
    for i in range(1, len(times)):
        if ratio <= times[i]:
            span = times[i] - times[i - 1]
            blend = 0.0 if span <= 0 else (ratio - times[i - 1]) / span
            return [a + (b - a) * blend for a, b in zip(values[i - 1], values[i])]
    return list(values[-1])


def _plugs(node, out, path=()):
    """把 Plug 树摊平成带绝对时间区间的条目（父级区间不裁剪，样本里本就是绝对值）。"""
    for plug in _all(node, 'Plug'):
        name = plug['values'].get('name')
        name = name if isinstance(name, str) else ''
        entry = {'name': name, 'path': list(path) + [name],
                 'start': _num(plug, 'start', 0.0), 'end': _num(plug, 'end', 1.0),
                 'loop': int(_num(plug, 'loop', 0)), 'objects': [], 'work': {}}
        for obj in _all(plug, 'Object'):
            kind = _object_kind(obj)
            if kind is None:
                continue
            entry['objects'].append({'kind': kind['tag'], 'node': kind})
        for tag in ('Color', 'Scale', 'Rot'):
            curve = _curve(_work(plug, tag))
            if curve:
                entry['work'][tag] = curve
        entry['sounds'] = [s['values'].get('file') for s in _all(_first(plug, 'Trigger') or {'children': []}, 'Sound')
                           if isinstance(s['values'].get('file'), str)]
        out.append(entry)
        _plugs(plug, out, entry['path'])
    return out


class Effect:
    """一份 VRA 的结构化视图；字段缺失就留空，不补猜。"""

    # 插件名是日文原文，词表来自实际抽样；只做「缩小浏览范围」用，不是语义结论。
    KEYWORDS = (
        ('muzzle', ('マズル', 'muzzle', '銃口')),
        ('blade', ('刀身', '剣', 'ソード', 'saber', 'セイバー', '刃')),
        ('beam', ('ビーム', 'beam', '照射', 'レーザー')),
        ('explosion', ('爆炎', '爆発', '爆煙', '破片', '爆炸', '炸')),
        ('smoke', ('煙', 'スモーク', 'smoke', 'smork')),
        ('trail', ('軌跡', '轨迹', '残像', 'trail')),
        ('spark', ('火花', '電撃', '電気', 'spark')),
        ('aura', ('オーラ', 'aura', '発光', 'グロー', 'glow')),
        ('thruster', ('スラスター', 'バーニア', '噴出', 'varnair', 'thruster', '推進')),
        ('shield', ('シールド', 'shield')),
        ('ui', ('文字', '枠', 'ゲージ', 'チュートリアル', 'MissionStart', 'mesg', 'マウス')),
    )
    # 主标签顺序：越靠前越具体
    PRIORITY = ('muzzle', 'blade', 'beam', 'explosion', 'smoke', 'spark', 'trail',
                'aura', 'thruster', 'shield', 'ui', 'model', 'attached', 'other')

    def __init__(self, path, tree):
        self.path = str(path).replace('\\', '/')
        self.tree = tree
        header = _first({'children': tree}, 'Header')
        target = _first({'children': tree}, 'Target')
        self.frame = int(_num(header, 'frame', 0)) if header else 0
        self.loop = int(_num(header, 'loop', 0)) if header else 0
        self.target = {
            'type': int(_num(target, 'type', 0)) if target else 0,
            'find_socket': int(_num(target, 'find_socket', 0)) if target else 0,
            'owner': (target['values'].get('owner_name') if target and isinstance(target['values'].get('owner_name'), str) else ''),
        }
        self.plugs = _plugs({'children': tree}, [])
        refs = []
        _walk_value_files({'values': {}, 'children': tree}, refs)
        self.files = list(dict.fromkeys(refs))
        self.textures = [f for f in self.files if f.lower().endswith(('.png', '.tga', '.dds', '.bmp'))]
        self.attr_models = [f for f in self.files if f.lower().endswith('.vra')]
        self.dxg = [f for f in self.files if f.lower().endswith('.dxg')]
        self.sounds = [f for p in self.plugs for f in p['sounds'] if f]
        self.kinds = sorted({o['kind'] for p in self.plugs for o in p['objects']})
        self.plug_names = [p['name'] for p in self.plugs]
        self.tags = self._classify()

    # ---- 分类 -------------------------------------------------------------
    def _classify(self):
        """结构 + 插件名关键词给标签。一个特效可以有多个标签，主标签按 PRIORITY 取。"""
        names = ' '.join(self.plug_names)
        lower = names.lower()
        tags = []
        for tag, words in self.KEYWORDS:
            if any((w.lower() in lower) for w in words):
                tags.append(tag)
        # 结构证据：不依赖命名，命中就补标签
        if 'Trail' in self.kinds and 'trail' not in tags:
            tags.append('trail')
        if ('Model' in self.kinds or self.attr_models) and 'model' not in tags:
            tags.append('model')
        if self.target['owner'] and 'attached' not in tags:
            tags.append('attached')
        if not tags:
            tags.append('other')
        return tags

    @property
    def primary(self):
        for tag in self.PRIORITY:
            if tag in self.tags:
                return tag
        return 'other'

    # ---- 预览辅助 ---------------------------------------------------------
    def active(self, ratio):
        """t（0..1）时刻在场的对象：把 plug 的 start/end 当作绝对时间。"""
        items = []
        for plug in self.plugs:
            if not plug['objects']:
                continue
            if not (plug['start'] - 1e-6 <= ratio <= plug['end'] + 1e-6):
                continue
            span = plug['end'] - plug['start']
            local = 0.0 if span <= 0 else min(1.0, max(0.0, (ratio - plug['start']) / span))
            for obj in plug['objects']:
                items.append({'plug': plug, 'object': obj, 'local': local})
        return items

    def best_ratio(self):
        """挑一个“画面上最满”的采样时刻，供缩略图用。

        按在场对象的屏幕面积估权重（Sprite/Particle 用 dims 乘积，Model 给固定值）。
        这只是取景用的启发式，不代表特效的高潮帧。
        """
        best, best_score = 0.3, -1.0
        for step in range(1, 20):
            ratio = step / 20
            score = 0.0
            for item in self.active(ratio):
                node = item['object']['node']
                if item['object']['kind'] in ('Sprite', 'Particle'):
                    dims = node['values'].get('dims') or [1.0, 1.0]
                    score += abs(float(dims[0]) * float(dims[1]))
                else:
                    score += 60.0
            if score > best_score:
                best, best_score = ratio, score
        return best

    def texture_weight(self):
        return sum(1 for p in self.plugs for o in p['objects'] if o['kind'] in ('Sprite', 'Particle'))


def load(path):
    tree = parse_tree(Path(path).read_text('cp932', errors='replace'))
    return Effect(path, tree)


def signature_text(effect):
    """给浏览器列表用的一行摘要。"""
    bits = []
    if effect.frame:
        bits.append('%d帧' % effect.frame)
    bits.append('循环' if effect.loop else '单次')
    if effect.target['owner']:
        bits.append('@' + effect.target['owner'])
    if effect.kinds:
        bits.append('/'.join(effect.kinds))
    return ' · '.join(bits)
