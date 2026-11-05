"""Bounded reader for DXG 1.8 / 1.5 static mesh streams; no skeleton animation.

1.5 只出现在 fx/ 下的特效模型（如光束刀刃 PM_02_001_02.dxg），区块与组头布局
与 1.8 逐字段一致，因此共用同一套读取；其它版本一律拒绝，不猜。
"""
import math
import struct

MAGIC_18 = b'DXG \x01\x00\x08\x00'
MAGIC_15 = b'DXG \x01\x00\x05\x00'
VERSIONS = {MAGIC_18: '1.8', MAGIC_15: '1.5'}
SOCKET_TAIL = 72  # 两个 u32 之后紧跟 4x4 矩阵


def _socket(data, offset, end):
    """武器外观的挂点块也写作 kind=1，但不是网格流。

    布局：u32 flag(=1) u32 size u32 name_len（含 4 字节对齐）名字 u32 u32 4x4 矩阵。
    用「块长 == 12 + name_len + 72」逐字节核对，避免把真正的网格组误判成挂点。
    """
    if end - offset < 12:
        return None
    size, = struct.unpack_from('<I', data, offset + 8)
    if not 0 < size <= 64 or end - offset != 12 + size + SOCKET_TAIL:
        return None
    name = data[offset + 12:offset + 12 + size].split(b'\0')[0]
    if not name or any(c < 0x20 or c > 0x7e for c in name):
        return None
    return [{'name': name.decode('ascii'),
             'matrix': list(struct.unpack_from('<16f', data, end - 64))}]


def _nodes(data, offset, end):
    """kind=2 是节点块：若干名字 + 等量 4x4 矩阵。

    军刀的 s_shot01（刀柄端）/ s_shot02（刀尖）就在这里；网格节点也走同一种块，
    所以只在名字像挂点时才收。名字数与矩阵数不一致时整块跳过，不猜配对。
    """
    if end - offset < 16:
        return []
    name_len, = struct.unpack_from('<I', data, offset + 8)
    if not 0 < name_len <= 256 or offset + 12 + name_len + 8 > end:
        return []
    names = [s.decode('ascii', 'replace')
             for s in data[offset + 12:offset + 12 + name_len].split(b'\0') if s]
    tail = end - (offset + 12 + name_len + 8)
    if not names or tail <= 0 or tail % 64:
        return []
    count = tail // 64
    if count != len(names):
        return []
    found = []
    for i, name in enumerate(names):
        if not _is_socket_name(name):
            continue
        found.append({'name': name,
                      'matrix': list(struct.unpack_from('<16f', data, end - (count - i) * 64))})
    return found


def _is_socket_name(name):
    lowered = name.lower()
    return lowered.startswith(('s_shot', 's_wpn', 's_vnr', 's_ex')) or 'shot' in lowered



def parse(data):
    def unpack(fmt, offset):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(data):
            raise ValueError('DXG数据越界')
        return struct.unpack_from(fmt, data, offset)
    version = VERSIONS.get(data[:8])
    if version is None:
        raise ValueError('暂不支持此DXG版本')
    string_size = unpack('<I', 20)[0]
    offset = 24 + string_size
    if offset > len(data): raise ValueError('DXG名称表越界')
    names = [s.decode('utf8', 'replace') for s in data[24:offset].split(b'\0') if s]
    meshes, warnings = [], []
    sockets = []
    while offset + 8 <= len(data):
        kind, size = unpack('<II', offset)
        end = offset + 8 + size
        if end > len(data) or not size: raise ValueError('DXG区块长度无效')
        if kind == 2:
            sockets.extend(_nodes(data, offset, end))
            offset = end
            continue
        if kind == 1:
            socket = _socket(data, offset, end)
            if socket:
                sockets.extend(socket)
                offset = end
                continue
            tag, inner_size = unpack('<II', offset + 12)
            if tag not in (0xff01, 0xff02):
                warnings.append('未知网格流: ' + hex(tag))
            else:
                start = offset + 20
                np, nn, nu, _, _, nv, nt, nb, _, _ = unpack('<HHIIIHHIII', start)
                if max(np, nn, nu, nv, nt, nb) > 100000 or not np:
                    raise ValueError('DXG网格计数无效')
                p = start + 32
                groups = []
                for group in range(tag & 255):
                    if group:
                        nv, nt, nb, _, _ = unpack('<HHIII', p)
                        p += 16
                    refs = [unpack('<5H', p + i * 10) for i in range(nv)]
                    p += nv * 10
                    indices = list(unpack('<' + str(nt * 3) + 'H', p))
                    p += nt * 6
                    if nb:
                        bone_string_len = unpack('<I', p)[0]
                        p += 4 + bone_string_len + nv * 4
                    if any(i >= nv for i in indices): raise ValueError('DXG三角索引越界')
                    groups.append((refs, indices))
                refs, indices = [], []
                for group_refs, group_indices in groups:
                    base = len(refs)
                    refs.extend(group_refs)
                    indices.extend(i + base for i in group_indices)
                positions = unpack('<' + str(np * 3) + 'f', p)
                p += np * 12
                normals = unpack('<' + str(nn * 3) + 'f', p)
                p += nn * 12
                uvs = unpack('<' + str(nu * 2) + 'f', p)
                if p + nu * 8 > end:
                    raise ValueError('DXG网格索引无效')
                outp, outn, outuv = [], [], []
                for pi, ni, ui, _, _ in refs:
                    if pi >= np or ni >= nn or ui >= nu: raise ValueError('DXG属性索引无效')
                    outp.extend(positions[pi*3:pi*3+3])
                    outn.extend(normals[ni*3:ni*3+3])
                    outuv.extend(uvs[ui*2:ui*2+2])
                if not all(math.isfinite(v) and abs(v) < 1e7 for v in outp + outn + outuv):
                    raise ValueError('DXG包含无效浮点数')
                i = len(meshes)
                meshes.append({'name': names[i] if i < len(names) else 'mesh_' + str(i),
                               'positions': outp, 'normals': outn, 'uvs': outuv,
                               'indices': indices})
        offset = end
    if not meshes: raise ValueError('未找到可预览网格')
    return {'meshes': meshes, 'sockets': sockets, 'warnings': warnings, 'version': version,
            'preview_mode': '静态原始姿态；未应用动画与游戏材质'}
