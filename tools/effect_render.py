"""把武器外观网格与 VRA 特效合成一张预览图（离线，PIL + numpy）。

用途是让人肉眼判断「这个特效配这把枪/这把刀」是否合适，不追求还原客户端渲染：
- 武器按静态 DXG 网格做正交投影 + 平面着色；
- Sprite/Particle 按插件 Color/Scale 曲线取当下值，在挂点处做屏幕对齐贴图；
- Model 类对象（光束刀刃等）按其 attr VRA 指向的 DXG 画出加算剪影；
- 混合模式、帧率、粒子发射都是近似，页面上会如实标出，不能当作渲染验收。

坐标系：武器模型沿 +Z 为枪口方向、+Y 向上（来自 EM_02_0106_01 的包围盒与实际挂点）。
"""
import math
import sys
from functools import lru_cache
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / 'model_matcher'))
from dxg import parse as parse_dxg  # noqa: E402
from effect_lib import load as load_effect, sample  # noqa: E402

# ---------------------------------------------------------------- 资源读取
@lru_cache(maxsize=64)
def load_model(path):
    return parse_dxg(Path(path).read_bytes())


@lru_cache(maxsize=256)
def load_texture(path):
    with Image.open(path) as image:
        image = image.convert('RGBA')
        image.thumbnail((256, 256))
        return image.copy()


def texture_average(path):
    try:
        image = load_texture(path).convert('RGB')
    except Exception:
        return (150, 150, 158)
    small = np.asarray(image.resize((8, 8), Image.Resampling.BILINEAR), dtype=np.float32)
    return tuple(int(x) for x in small.reshape(-1, 3).mean(0))


def resolve(assets, relative):
    relative = relative.replace('\\', '/').lstrip('./')
    return Path(assets) / relative


def weapon_texture(assets, dxg_path):
    """武器贴图取同资源目录 tex/ 下第一张，给模型一个整体色调（并提亮到可辨认）。"""
    folder = Path(dxg_path).parent.parent / 'tex'
    color = (150, 150, 158)
    if folder.is_dir():
        files = sorted(folder.glob('*.*'))
        if files:
            color = texture_average(files[0])
    top = max(color) or 1
    gain = 168.0 / top
    return tuple(min(255, int(c * gain)) for c in color)


# ---------------------------------------------------------------- 数学
def rotate(point, yaw, pitch):
    x, y, z = point
    cy, sy = math.cos(yaw), math.sin(yaw)
    x, z = x * cy + z * sy, -x * sy + z * cy
    cp, sp = math.cos(pitch), math.sin(pitch)
    y, z = y * cp - z * sp, y * sp + z * cp
    return x, y, z


def mat4_scale(scale):
    return [scale[0], 0.0, 0.0, 0.0, 0.0, scale[1], 0.0, 0.0, 0.0, 0.0, scale[2], 0.0, 0.0, 0.0, 0.0, 1.0]


def mat4_rot(degrees):
    """欧拉 XYZ（角度）→ 行主序 4x4；VRA 的 Rot 单位是度。"""
    rx, ry, rz = (math.radians(v) for v in degrees)
    cx, sx = math.cos(rx), math.sin(rx)
    cy, sy = math.cos(ry), math.sin(ry)
    cz, sz = math.cos(rz), math.sin(rz)
    mx = [1, 0, 0, 0, 0, cx, -sx, 0, 0, sx, cx, 0, 0, 0, 0, 1]
    my = [cy, 0, sy, 0, 0, 1, 0, 0, -sy, 0, cy, 0, 0, 0, 0, 1]
    mz = [cz, -sz, 0, 0, sz, cz, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]
    return mat4_mul(mz, mat4_mul(my, mx))


def mat4_mul(a, b):
    out = [0.0] * 16
    for r in range(4):
        for c in range(4):
            out[r * 4 + c] = sum(a[r * 4 + k] * b[k * 4 + c] for k in range(4))
    return out


def apply(m, point):
    x, y, z = point
    return (m[0] * x + m[1] * y + m[2] * z + m[3],
            m[4] * x + m[5] * y + m[6] * z + m[7],
            m[8] * x + m[9] * y + m[10] * z + m[11])


def normalize(v):
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return tuple(x / n for x in v)


def pad(values, size, fill=0.0):
    """VRA 的数组常只有一个关键值（如 rot 只给 1 个数），统一下补齐。"""
    values = list(values or [])
    return (values + [fill] * size)[:size]


def align_matrix(points):
    """把最长的轴转到 +Z，让枪管/刀身在画面上横向展开。

    枪的长轴是 Z，军刀的长轴是 Y；不统一就会把刀竖着画。
    """
    low = [min(p[i] for p in points) for i in range(3)]
    high = [max(p[i] for p in points) for i in range(3)]
    spans = [high[i] - low[i] for i in range(3)]
    axis = spans.index(max(spans))
    if axis == 1:
        return mat4_rot([90.0, 0.0, 0.0])   # Y -> Z
    if axis == 0:
        return mat4_rot([0.0, -90.0, 0.0])  # X -> Z
    return mat4_rot([0.0, 0.0, 0.0])


class Projector:
    """正交投影 + 居中缩放；画布坐标 y 向下，视图空间 z 越大越靠近相机。"""

    def __init__(self, points, size, margin=0.10, yaw=58.0, pitch=16.0, floor_scale=0.0):
        self.size = size
        self.yaw, self.pitch = math.radians(yaw), math.radians(pitch)
        self.align = align_matrix(points)
        view = [self.view(p) for p in points]
        xs = [v[0] for v in view]
        ys = [v[1] for v in view]
        self.cx = (max(xs) + min(xs)) / 2
        self.cy = (max(ys) + min(ys)) / 2
        span_x = max(max(xs) - min(xs), 1e-6)
        span_y = max(max(ys) - min(ys), 1e-6)
        usable_w = size[0] * (1 - 2 * margin)
        usable_h = size[1] * (1 - 2 * margin)
        self.scale = min(usable_w / span_x, usable_h / span_y)
        # 特效可以是几百单位的大爆炸/光锥；不允许把它放大到武器只剩一个点
        if floor_scale:
            self.scale = max(self.scale, floor_scale)
        self.origin = (size[0] / 2, size[1] / 2)

    def view(self, point):
        return rotate(apply(self.align, point), self.yaw, self.pitch)

    def __call__(self, point):
        x, y, z = self.view(point)
        return (self.origin[0] + (x - self.cx) * self.scale,
                self.origin[1] - (y - self.cy) * self.scale,
                z)


# ---------------------------------------------------------------- 绘制
def shade(base, normal_view, light=(0.42, 0.62, 0.66)):
    light = normalize(light)
    value = max(0.0, sum(a * b for a, b in zip(normal_view, light)))
    k = 0.34 + 0.78 * value
    return tuple(min(255, int(c * k)) for c in base)


def draw_mesh(canvas, model, project, base=(150, 150, 158), alpha=255, additive=False, soft=0):
    """画家算法：按面心深度从远到近填充；亮度用视图空间法线算，不能拿屏幕叉积。

    soft>0 时先把整层画到空画布再做高斯模糊，用来柔化能量体的多边形硬边
    （刀刃外层的辉光锥是低面数面片，直接填色会像一块硬纸板）。
    """
    faces = []
    for mesh in model['meshes']:
        positions = mesh['positions']
        indices = mesh['indices']
        view = [project.view(positions[i * 3:i * 3 + 3]) for i in range(len(positions) // 3)]
        screen = [project(v) for v in view]
        for t in range(0, len(indices), 3):
            a, b, c = indices[t], indices[t + 1], indices[t + 2]
            va, vb, vc = view[a], view[b], view[c]
            ux, uy, uz = vb[0] - va[0], vb[1] - va[1], vb[2] - va[2]
            wx, wy, wz = vc[0] - va[0], vc[1] - va[1], vc[2] - va[2]
            nx, ny, nz = uy * wz - uz * wy, uz * wx - ux * wz, ux * wy - uy * wx
            norm = math.sqrt(nx * nx + ny * ny + nz * nz)
            if norm < 1e-6:
                continue
            n = (nx / norm, ny / norm, nz / norm)
            if n[2] < 0:  # 背面法线翻向相机，双面都受光
                n = (-n[0], -n[1], -n[2])
            depth = (va[2] + vb[2] + vc[2]) / 3
            pa, pb, pc = screen[a], screen[b], screen[c]
            if abs((pb[0] - pa[0]) * (pc[1] - pa[1]) - (pb[1] - pa[1]) * (pc[0] - pa[0])) < 0.05:
                continue
            faces.append((depth, pa, pb, pc, n))
    target = Image.new('RGBA', canvas.size, (0, 0, 0, 0)) if additive else canvas
    draw = ImageDraw.Draw(target, 'RGBA')
    for _depth, pa, pb, pc, n in sorted(faces, key=lambda f: f[0]):
        color = shade(base, n)
        draw.polygon([(pa[0], pa[1]), (pb[0], pb[1]), (pc[0], pc[1])], fill=color + (alpha,))
    if not additive:
        return canvas
    if soft:
        target = target.filter(ImageFilter.GaussianBlur(soft))
    return add_layer(canvas, target)


def add_layer(canvas, layer):
    """加算叠一层（能量特效要发光感，不能实心盖住武器）。"""
    base = np.asarray(canvas, dtype=np.float32)
    over = np.asarray(layer, dtype=np.float32)
    weight = over[:, :, 3:4] / 255.0
    base[:, :, :3] = np.clip(base[:, :, :3] + over[:, :, :3] * weight, 0, 255)
    return Image.fromarray(base.astype(np.uint8), 'RGBA')


def add_sprite(canvas, image, center, size, color=(1, 1, 1, 1), additive=True, rotation=0.0):
    """把一张贴图按屏幕尺寸叠到画布上；additive 走加算，否则常规 alpha。"""
    if size[0] < 0.6 or size[1] < 0.6:
        return canvas
    sprite = image.convert('RGBA').resize(
        (max(1, int(size[0])), max(1, int(size[1]))), Image.Resampling.BILINEAR)
    if rotation:
        sprite = sprite.rotate(rotation, resample=Image.Resampling.BICUBIC, expand=True)
    r, g, b, a = sprite.split()
    a = a.point(lambda v: int(v * min(1.0, max(0.0, color[3]))))
    sprite = Image.merge('RGBA', (
        r.point(lambda v: int(v * color[0])),
        g.point(lambda v: int(v * color[1])),
        b.point(lambda v: int(v * color[2])),
        a))
    left = int(center[0] - sprite.width / 2)
    top = int(center[1] - sprite.height / 2)
    layer = Image.new('RGBA', canvas.size, (0, 0, 0, 0))
    layer.paste(sprite, (left, top))
    if additive:
        return add_layer(canvas, layer)
    return Image.alpha_composite(canvas, layer)


def glow(image, radius=3, strength=0.55):
    """给整体加一层柔光，接近发光特效在游戏里的观感。"""
    blur = image.filter(ImageFilter.GaussianBlur(radius))
    a = np.asarray(image, dtype=np.float32)
    b = np.asarray(blur, dtype=np.float32)
    out = np.clip(a * (1 - strength) + b * strength * 1.25, 0, 255)
    return Image.fromarray(out.astype(np.uint8), 'RGBA')


# ---------------------------------------------------------------- 组合
def pick_socket(sockets, owner):
    names = [(s['name'] or '').lower() for s in sockets]
    if owner:
        for i, name in enumerate(names):
            if name == owner.lower():
                return sockets[i], 'exact'
    for i, name in enumerate(names):
        if name == 's_shot01':
            return sockets[i], 's_shot01'
    for i, name in enumerate(names):
        if name.startswith('s_shot'):
            return sockets[i], 'first_shot'
    return None, 'none'


def _socket_point(socket):
    m = socket['matrix']
    return (m[12], m[13], m[14])


def front_point(model):
    """没有挂点时用包围盒前端（+Z 最大处）代替。"""
    top = None
    for mesh in model['meshes']:
        p = mesh['positions']
        for i in range(0, len(p), 3):
            if top is None or p[i + 2] > top[2]:
                top = (p[i], p[i + 1], p[i + 2])
    return top or (0.0, 0.0, 0.0)


def _instructions(assets, effect, ratio, anchor):
    """把 t 时刻在场的对象解析成世界坐标下的绘制指令，取景与绘制两趟共用。"""
    out = []
    for item in effect.active(ratio):
        plug, obj, local = item['plug'], item['object'], item['local']
        node = obj['node']
        if obj['kind'] in ('Sprite', 'Particle'):
            files = node['values'].get('file') or []
            if isinstance(files, str):
                files = [files]
            path = resolve(assets, files[0]) if files else None
            if path is None or not path.exists():
                out.append({'kind': 'skip', 'label': '%s(%s)' % (
                    plug['name'], '无贴图' if path is None else '贴图缺失')})
                continue
            dims = pad(node['values'].get('dims'), 2, 1.0)
            tint = pad(node['values'].get('color'), 4, 1.0)
            scale = pad(sample(plug['work']['Scale'], local, 'scale', [1.0, 1.0, 1.0]), 3, 1.0) \
                if 'Scale' in plug['work'] else [1.0, 1.0, 1.0]
            if 'Color' in plug['work']:
                tint = pad(sample(plug['work']['Color'], local, 'color', tint), 4, 1.0)
            offset = pad(node['values'].get('pos'), 3, 0.0)
            rotation = 0.0
            if 'Rot' in plug['work']:
                rotation = pad(sample(plug['work']['Rot'], local, 'rot', [0.0, 0.0, 0.0]), 3, 0.0)[2]
            out.append({'kind': 'sprite', 'path': path, 'tint': tuple(tint),
                        'world': (anchor[0] + offset[0], anchor[1] + offset[1], anchor[2] + offset[2]),
                        'size': (abs(float(dims[0]) * float(scale[0])),
                                 abs(float(dims[1]) * float(scale[1]))),
                        'rotation': rotation,
                        'additive': int(node['values'].get('blend', [3])[0]) in (2, 3),
                        'label': '%s·%s' % (plug['name'], obj['kind'])})
        elif obj['kind'] == 'Model':
            attr = node['values'].get('file')
            if isinstance(attr, str):
                attr = [attr]
            built = _model_effect(assets, attr[0], plug, local, anchor) if attr else None
            if built:
                out.append(built)
            else:
                out.append({'kind': 'skip', 'label': '%s(模型缺失)' % plug['name']})
        elif obj['kind'] == 'Trail':
            files = node['values'].get('file') or []
            if isinstance(files, str):
                files = [files]
            path = resolve(assets, files[0]) if files else None
            if path is None or not path.exists():
                out.append({'kind': 'skip', 'label': '%s(轨迹无贴图)' % plug['name']})
                continue
            width = abs(float((node['values'].get('width') or [12.0])[0]))
            # 轨迹本应沿飞行路径拖尾；这里没有弹道，只在挂点后方拉一条同宽光带
            length = max(70.0, width * 1.8)
            tail = (anchor[0], anchor[1], anchor[2] - length)
            out.append({'kind': 'trail', 'path': path,
                        'tail': tail, 'world': anchor, 'width': width,
                        'tint': (1.0, 1.0, 1.0, 1.0),
                        'label': '%s·Trail(近似)' % plug['name']})
    return out


def _model_effect(assets, attr_relative, plug, local, origin):
    """Model 类特效：读 attr VRA → DXG，按插件 Rot/Scale 变换到挂点。"""
    attr_path = resolve(assets, attr_relative)
    if not attr_path.exists():
        return None
    attr = load_effect(attr_path)
    if not attr.dxg:
        return None
    dxg_path = resolve(assets, attr.dxg[0])
    if not dxg_path.exists():
        return None
    try:
        model = load_model(dxg_path)
    except Exception:
        return None
    scale = pad(sample(plug['work']['Scale'], local, 'scale', [1.0, 1.0, 1.0]), 3, 1.0) \
        if 'Scale' in plug['work'] else [1.0, 1.0, 1.0]
    rot = pad(sample(plug['work']['Rot'], local, 'rot', [0.0, 0.0, 0.0]), 3, 0.0) \
        if 'Rot' in plug['work'] else [0.0, 0.0, 0.0]
    transform = mat4_mul(mat4_rot(rot), mat4_scale([float(v) for v in scale]))
    meshes = []
    for mesh in model['meshes']:
        p = mesh['positions']
        out = []
        for i in range(0, len(p), 3):
            x, y, z = apply(transform, (p[i], p[i + 1], p[i + 2]))
            out.extend((x + origin[0], y + origin[1], z + origin[2]))
        meshes.append({'positions': out, 'indices': mesh['indices']})
    tint = texture_average(resolve(assets, attr.textures[0])) if attr.textures else (255, 255, 255)
    return {'kind': 'mesh', 'meshes': meshes, 'tint': tint,
            'label': '%s·Model' % plug['name']}


def compose(assets, weapon_path, effect, ratio, size=(520, 320), background=(24, 32, 42)):
    """渲染「武器 + 特效」一帧。返回 (PIL.Image, meta)。

    先按武器网格 + 特效几何一起取景，再画，避免大特效（刀刃、爆炸）把画面撑爆。
    """
    model = load_model(weapon_path)
    socket, how = pick_socket(model['sockets'], effect.target['owner'])
    anchor = _socket_point(socket) if socket else front_point(model)
    instructions = _instructions(assets, effect, ratio, anchor)

    points, weapon_points = [], []
    for mesh in model['meshes']:
        p = mesh['positions']
        weapon_points.extend((p[i], p[i + 1], p[i + 2]) for i in range(0, len(p), 3))
    points.extend(weapon_points)
    for item in instructions:
        if item['kind'] == 'sprite':
            cx, cy, cz = item['world']
            hw, hh = item['size'][0] / 2, item['size'][1] / 2
            points.extend((cx + dx, cy + dy, cz) for dx in (-hw, hw) for dy in (-hh, hh))
        elif item['kind'] == 'trail':
            points.extend(((item['world']), item['tail']))
        elif item['kind'] == 'mesh':
            for mesh in item['meshes']:
                p = mesh['positions']
                points.extend((p[i], p[i + 1], p[i + 2]) for i in range(0, len(p), 3))
    weapon_scale = Projector(weapon_points, size).scale
    project = Projector(points, size, floor_scale=weapon_scale / 4)

    canvas = Image.new('RGBA', size, background + (255,))
    draw_mesh(canvas, model, project, weapon_texture(assets, weapon_path))
    # 挂点标记：让人看清特效挂在哪
    marker = project(anchor)
    ImageDraw.Draw(canvas).ellipse(
        [(marker[0] - 2.5, marker[1] - 2.5), (marker[0] + 2.5, marker[1] + 2.5)],
        fill=(120, 210, 255, 190))

    drawn, skipped = [], []
    for item in instructions:
        if item['kind'] == 'skip':
            skipped.append(item['label'])
        elif item['kind'] == 'sprite':
            canvas = add_sprite(canvas, load_texture(item['path']), project(item['world']),
                                (item['size'][0] * project.scale, item['size'][1] * project.scale),
                                item['tint'], additive=item['additive'], rotation=item['rotation'])
            drawn.append(item['label'])
        elif item['kind'] == 'trail':
            head = project(item['world'])
            tail = project(item['tail'])
            dx, dy = tail[0] - head[0], tail[1] - head[1]
            length = math.hypot(dx, dy)
            if length > 1:
                angle = math.degrees(math.atan2(-dy, dx))
                center = ((head[0] + tail[0]) / 2, (head[1] + tail[1]) / 2)
                canvas = add_sprite(canvas, load_texture(item['path']), center,
                                    (length, max(2.0, item['width'] * project.scale)),
                                    item['tint'], additive=True, rotation=angle)
                drawn.append(item['label'])
        elif item['kind'] == 'mesh':
            # 能量体只做淡加算：刀刃外层的“板”是透明面片，实心填充会变成一块黑紫
            canvas = draw_mesh(canvas, {'meshes': item['meshes']}, project,
                               item['tint'], alpha=120, additive=True, soft=2.0)
            drawn.append(item['label'])

    notes = []
    if how == 'none':
        notes.append('该武器没有可识别挂点，特效位置按包围盒前端兜底')
    elif how != 'exact':
        notes.append('特效原本挂 %s，这里按 %s 预览'
                     % (effect.target['owner'] or '未指定', socket['name']))

    final = glow(canvas)
    ImageDraw.Draw(final).text((8, size[1] - 16),
                               't=%.2f  %s' % (ratio, effect.path.split('/')[-1]),
                               fill=(150, 168, 190, 255))
    meta = {'socket': socket['name'] if socket else None, 'socket_match': how,
            'drawn': drawn, 'skipped': skipped, 'notes': notes,
            'blend_note': '混合模式按 2/3=加算、1=常规近似；粒子只画代表样本，未模拟发射与飞行'}
    return final, meta

