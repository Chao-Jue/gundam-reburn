"""用 SendInput 往目标窗口发文字/点击/回车（D3D 游戏只认真实输入）。

例：
  python tools/sendinput.py --pid 38336 --focus click 1000 705 text 123 click 1000 735 text 123 click 960 820
  python tools/sendinput.py --pid 38336 key enter
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import win_shot

user32 = ctypes.WinDLL('user32', use_last_error=True)

INPUT_MOUSE = 0
INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_ABSOLUTE = 0x8000
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [('dx', wt.LONG), ('dy', wt.LONG), ('mouseData', wt.DWORD),
                ('dwFlags', wt.DWORD), ('time', wt.DWORD), ('dwExtraInfo', ctypes.POINTER(wt.ULONG))]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [('wVk', wt.WORD), ('wScan', wt.WORD), ('dwFlags', wt.DWORD),
                ('time', wt.DWORD), ('dwExtraInfo', ctypes.POINTER(wt.ULONG))]


class INPUT(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [('mi', MOUSEINPUT), ('ki', KEYBDINPUT)]
    _anonymous_ = ('u',)
    _fields_ = [('type', wt.DWORD), ('u', _U)]


def _send(inp):
    user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))


def click(x, y):
    sw, sh = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
    inp = INPUT(type=INPUT_MOUSE)
    inp.mi.dx = int(x * 65535 / (sw - 1))
    inp.mi.dy = int(y * 65535 / (sh - 1))
    inp.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE
    _send(inp)
    time.sleep(0.05)
    inp = INPUT(type=INPUT_MOUSE)
    inp.mi.dwFlags = MOUSEEVENTF_LEFTDOWN
    _send(inp)
    time.sleep(0.05)
    inp = INPUT(type=INPUT_MOUSE)
    inp.mi.dwFlags = MOUSEEVENTF_LEFTUP
    _send(inp)
    time.sleep(0.25)


def text(s):
    for ch in s:
        for up in (False, True):
            inp = INPUT(type=INPUT_KEYBOARD)
            inp.ki.wVk = 0
            inp.ki.wScan = ord(ch)
            inp.ki.dwFlags = KEYEVENTF_UNICODE | (KEYEVENTF_KEYUP if up else 0)
            _send(inp)
            time.sleep(0.03)
        time.sleep(0.05)


VK = {'enter': 0x0D, 'tab': 0x09, 'esc': 0x1B, 'back': 0x08, 'space': 0x20}


def key(name):
    vk = VK[name.lower()]
    inp = INPUT(type=INPUT_KEYBOARD)
    inp.ki.wVk = vk
    _send(inp)
    time.sleep(0.05)
    inp = INPUT(type=INPUT_KEYBOARD)
    inp.ki.wVk = vk
    inp.ki.dwFlags = KEYEVENTF_KEYUP
    _send(inp)
    time.sleep(0.2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=int)
    ap.add_argument('--focus', action='store_true')
    ap.add_argument('steps', nargs='+', help='click X Y | text STR | key NAME | sleep S')
    a = ap.parse_args()
    if a.focus:
        hwnd, _ = win_shot.find_window(a.pid, None)
        win_shot.force_foreground(hwnd)
        time.sleep(0.6)
    i = 0
    while i < len(a.steps):
        s = a.steps[i]
        if s == 'click':
            click(int(a.steps[i + 1]), int(a.steps[i + 2]))
            print('click', a.steps[i + 1], a.steps[i + 2])
            i += 3
        elif s == 'text':
            text(a.steps[i + 1])
            print('text', a.steps[i + 1])
            i += 2
        elif s == 'key':
            key(a.steps[i + 1])
            print('key', a.steps[i + 1])
            i += 2
        elif s == 'sleep':
            time.sleep(float(a.steps[i + 1]))
            i += 2
        else:
            raise SystemExit('unknown step ' + s)
    return 0


if __name__ == '__main__':
    sys.exit(main())
