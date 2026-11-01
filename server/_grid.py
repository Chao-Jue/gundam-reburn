"""抓图 + 裁剪放大 + 画坐标网格（每 50 屏幕像素一条线，主网格 100 标红）。

输出图上：屏幕坐标 = 裁剪起点 + 网格线计数 * 50。
"""
import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / 'tools'))
import win_shot


def load_png(p):
    import struct
    import zlib
    d = pathlib.Path(p).read_bytes()
    i = 8
    idat = b''
    w = h = None
    while i < len(d):
        ln = struct.unpack('>I', d[i:i + 4])[0]
        tag = d[i + 4:i + 8]
        data = d[i + 8:i + 8 + ln]
        i += 12 + ln
        if tag == b'IHDR':
            w, h = struct.unpack('>II', data[:8])
        elif tag == b'IDAT':
            idat += data
    raw = zlib.decompress(idat)
    stride = w * 3 + 1
    rows = [bytearray(raw[y * stride + 1:(y + 1) * stride]) for y in range(h)]
    return w, h, rows


def save_rgb(path, w, h, rows):
    import struct
    import zlib
    raw = b''.join(b'\x00' + bytes(r) for r in rows)

    def chunk(tag, data):
        return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag + data) & 0xFFFFFFFF)

    png = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
           + chunk(b'IDAT', zlib.compress(raw, 6)) + chunk(b'IEND', b''))
    pathlib.Path(path).write_bytes(png)


ap = argparse.ArgumentParser()
ap.add_argument('--pid', type=int)
ap.add_argument('--src', default=None, help='已有 png（不抓图）')
ap.add_argument('--rect', required=True)
ap.add_argument('--scale', type=int, default=2)
ap.add_argument('--out', required=True)
a = ap.parse_args()

x0, y0, x1, y1 = [int(v) for v in a.rect.split(',')]
if a.src:
    sw, sh, srows = load_png(a.src)
else:
    hwnd, rect = win_shot.find_window(a.pid, None)
    sw, sh, buf, ok = win_shot.grab(hwnd, rect, True)
    srows = []
    for y in range(sh):
        row = bytearray(sw * 3)
        for x in range(sw):
            o = (y * sw + x) * 4
            row[x * 3] = buf[o + 2]
            row[x * 3 + 1] = buf[o + 1]
            row[x * 3 + 2] = buf[o]
        srows.append(row)

cw, ch = x1 - x0, y1 - y0
s = a.scale
out = []
for yy in range(ch * s):
    sy = y0 + yy // s
    src = srows[sy]
    row = bytearray(cw * s * 3)
    for xx in range(cw * s):
        sx = x0 + xx // s
        row[xx * 3:xx * 3 + 3] = src[sx * 3:sx * 3 + 3]
    out.append(row)

# 画网格：屏幕 x 是 50 的倍数就画
for gx in range((x0 // 50) * 50, x1 + 1, 50):
    cx = (gx - x0) * s
    if 0 <= cx < cw * s:
        major = (gx % 100 == 0)
        col = (255, 0, 0) if major else (0, 255, 255)
        for yy in range(ch * s):
            out[yy][cx * 3:cx * 3 + 3] = bytes(col)
for gy in range((y0 // 50) * 50, y1 + 1, 50):
    cy = (gy - y0) * s
    if 0 <= cy < ch * s:
        major = (gy % 100 == 0)
        col = (255, 0, 0) if major else (0, 255, 255)
        row = out[cy]
        for xx in range(cw * s):
            row[xx * 3:xx * 3 + 3] = bytes(col)

save_rgb(a.out, cw * s, ch * s, out)
print('saved', a.out, 'crop', x0, y0, x1, y1, 'grid: 红线=100的倍数坐标')
