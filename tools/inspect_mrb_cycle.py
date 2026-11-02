"""Read-only endpoint audit for the sampled MRB 1.0 indexed animation layout.

Reports continuity, not semantic animation labels or a recommended playback order.
No client asset is modified or copied into the repository.
"""
import argparse
import json
import math
import struct
from pathlib import Path


def endpoints(data):
    def read(fmt, offset):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(data):
            raise ValueError('truncated MRB')
        return struct.unpack_from(fmt, data, offset)

    if data[:8] != b'MRB\0\0\0\1\0' or read('<I', 0x38)[0] != 1:
        raise ValueError('unsupported MRB layout')
    size = read('<I', 0x3c)[0]
    pos = 0x40 + size
    if pos > len(data):
        raise ValueError('truncated MRB names')
    names = [s.decode('utf-8') for s in data[0x40:pos].split(b'\0') if s]
    count, width = read('<II', pos)
    pos += 8
    if not count or width != 4 or count > (len(data)-pos)//4:
        raise ValueError('unsupported MRB time stream')
    ticks = read('<' + 'I'*count, pos)
    if any(a > b for a, b in zip(ticks, ticks[1:])):
        raise ValueError('nonmonotonic MRB times')
    pos += count*4
    if read('<3I', pos) != (1, 4, 200):
        raise ValueError('unsupported MRB indexed stream')
    pos += 12
    pools = []
    for components in (3, 4, 3):
        length, stride = read('<II', pos)
        pos += 8
        if stride != components*4 or length > (len(data)-pos)//stride:
            raise ValueError('invalid MRB value pool')
        values = [read('<'+'f'*components, pos+i*stride) for i in range(length)]
        if any(not math.isfinite(v) for row in values for v in row):
            raise ValueError('nonfinite MRB value')
        pools.append(values)
        pos += length*stride
    bones, stride = read('<II', pos)
    pos += 8
    if bones != len(names) or len(set(names)) != bones or stride != count*6:
        raise ValueError('unsupported MRB bone stream')
    if pos + bones*stride != len(data):
        raise ValueError('MRB bone stream length mismatch')
    rotations = {}
    for i, name in enumerate(names):
        frames = []
        for frame in range(count):
            indices = read('<3H', pos+i*stride+frame*6)
            if any(index >= len(pool) for index, pool in zip(indices, pools)):
                raise ValueError('MRB pool index out of range')
            if frame in (0, count-1):
                frames.append(pools[1][indices[1]])
        rotations[name] = (frames[0], frames[-1])
    return {'frames': count, 'ticks': (ticks[0], ticks[-1]), 'rotations': rotations}


def angle_degrees(left, right):
    norm = math.sqrt(sum(v*v for v in left)*sum(v*v for v in right))
    if not norm:
        raise ValueError('zero quaternion')
    dot = abs(sum(a*b for a, b in zip(left, right))) / norm
    return math.degrees(2*math.acos(min(1, dot)))


def compare(left, right, bones):
    return {name: round(angle_degrees(left['rotations'][name][1],
                                     right['rotations'][name][0]), 4) for name in bones}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('left', type=Path)
    parser.add_argument('right', type=Path)
    parser.add_argument('--bones', nargs='+', default=['T_L_Thigh', 'T_R_Thigh', 'T_L_Knee', 'T_R_Knee'])
    args = parser.parse_args()
    a, b = (endpoints(path.read_bytes()) for path in (args.left, args.right))
    print(json.dumps({'left_frames': a['frames'], 'right_frames': b['frames'],
                      'left_self': compare(a, a, args.bones),
                      'right_self': compare(b, b, args.bones),
                      'left_to_right': compare(a, b, args.bones),
                      'right_to_left': compare(b, a, args.bones)}, indent=2))
