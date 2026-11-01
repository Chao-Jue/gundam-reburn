"""抓一张客户端窗口图并按 Rect 裁剪放大保存（不需要 PIL）。"""
import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / 'tools'))
import win_shot

ap = argparse.ArgumentParser()
ap.add_argument('--pid', type=int)
ap.add_argument('--class', dest='cls', default=None)
ap.add_argument('--rect', required=True, help='x0,y0,x1,y1 (窗口坐标)')
ap.add_argument('--scale', type=int, default=2)
ap.add_argument('--out', default=r'D:\project\gundam-reburn\server\_crop.png')
ap.add_argument('--focus', action='store_true')
a = ap.parse_args()

hwnd, rect = win_shot.find_window(a.pid, a.cls)
if a.focus:
    win_shot.force_foreground(hwnd)
w, h, buf, ok = win_shot.grab(hwnd, rect, True)
x0, y0, x1, y1 = [int(v) for v in a.rect.split(',')]
x0, y0 = max(0, x0), max(0, y0)
x1, y1 = min(w, x1), min(h, y1)
cw, ch = x1 - x0, y1 - y0
s = max(1, a.scale)
out = bytearray(cw * s * ch * s * 4)
for yy in range(ch * s):
    sy = y0 + yy // s
    srow = buf[sy * w * 4:(sy + 1) * w * 4]
    drow = bytearray(cw * s * 4)
    for xx in range(cw * s):
        sx = x0 + xx // s
        drow[xx * 4:xx * 4 + 4] = srow[sx * 4:sx * 4 + 4]
    out[yy * cw * s * 4:(yy + 1) * cw * s * 4] = drow
win_shot.save_png(pathlib.Path(a.out), cw * s, ch * s, bytes(out))
print('saved', a.out, cw * s, ch * s, 'window', w, h, 'ok', ok)
