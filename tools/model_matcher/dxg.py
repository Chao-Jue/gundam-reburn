"""Bounded reader for DXG 1.8 static mesh streams; no skeleton animation."""
import math
import struct


def parse(data):
    def unpack(fmt, offset):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(data):
            raise ValueError('DXG数据越界')
        return struct.unpack_from(fmt, data, offset)
    if data[:8] != b'DXG \x01\x00\x08\x00':
        raise ValueError('暂不支持此DXG版本')
    string_size = unpack('<I', 20)[0]
    offset = 24 + string_size
    if offset > len(data): raise ValueError('DXG名称表越界')
    names = [s.decode('utf8', 'replace') for s in data[24:offset].split(b'\0') if s]
    meshes, warnings = [], []
    while offset + 8 <= len(data):
        kind, size = unpack('<II', offset)
        end = offset + 8 + size
        if end > len(data) or not size: raise ValueError('DXG区块长度无效')
        if kind == 1:
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
    return {'meshes': meshes, 'warnings': warnings,
            'preview_mode': '静态原始姿态；未应用动画与游戏材质'}
