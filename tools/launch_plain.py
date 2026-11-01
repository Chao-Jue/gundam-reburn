#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""不注入 frida、不伪造 CPS，直接带 cpsoff 启动客户端。

背景（见 server/cpsoff-验证-2026-11-01.md）：
客户端 `0x5836xx` 在加载 `ACOPCShell.dll` 之前会扫命令行参数，见到以 `cpsoff`
开头的参数就置 `[0x117B7A0]=1` 并完全跳过 CPS，因此：
    - 不需要管理员（驱动 IOCTL 链不参与）
    - 不需要 frida 注入，也不需要伪造 LoadLibraryW / DeviceIoControl
    - 服务端照常由 fake_http + fake_auth 提供

用法：
    python tools/launch_plain.py                      # 默认 ./data/ + cpsoff
    python tools/launch_plain.py --seconds 600
    python tools/launch_plain.py --arg ./data/ --extra-args "cpsoff"

注意：客户端启动后会自己重启/提权一次，`Popen` 拿到的 pid 通常 0.5 秒就退出
（exitcode=0），真正在跑的是新 pid。所以这里按镜像名跟踪，不按 pid。
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = 'GundamOnline_CHINA.exe'


def find_exe() -> Path:
    for path in sorted((ROOT / 'launcher').rglob(IMAGE)):
        return path
    raise SystemExit('找不到 %s（先确认 launcher 目录在本机）' % IMAGE)


def running() -> bool:
    """按镜像名判断客户端是否还活着（输出按 GBK 编码，只做字节匹配）。"""
    try:
        out = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq %s' % IMAGE, '/NH'],
                             capture_output=True)
    except OSError:
        return False
    return IMAGE.encode('ascii') in out.stdout


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='带 cpsoff 纯原生启动客户端（无 frida / 无 CPS 伪造）')
    parser.add_argument('--arg', dest='game_args', default='./data/', help='第一个参数，默认 ./data/')
    parser.add_argument('--extra-args', dest='extra', default='cpsoff',
                        help='额外参数（空格分隔），默认 cpsoff')
    parser.add_argument('--seconds', type=float, default=3000.0, help='最长跟踪时间')
    parser.add_argument('--no-dpi-fix', action='store_true',
                        help='不设置 __COMPAT_LAYER=HIGHDPIAWARE')
    parser.add_argument('--kill', action='store_true', help='超时后结束客户端（需要管理员）')
    args = parser.parse_args(argv)

    exe = find_exe()
    argv_game = [str(exe)] + ([args.game_args] if args.game_args else [])
    argv_game += [s for s in (args.extra or '').split() if s]

    env = dict(os.environ)
    if not args.no_dpi_fix:
        layer = env.get('__COMPAT_LAYER', '').strip()
        if 'HIGHDPIAWARE' not in layer.upper():
            env['__COMPAT_LAYER'] = (layer + ' HIGHDPIAWARE').strip()

    print('[*] 启动: %s' % ' '.join(argv_game))
    print('[*] 工作目录: %s' % exe.parent)
    print('[*] frida: 关闭   CPS 伪造: 关闭   管理员: 不需要（客户端会自己提权，可能弹一次 UAC）')
    try:
        child = subprocess.Popen(argv_game, cwd=str(exe.parent), env=env)
    except OSError as error:
        print('[!] 启动失败: %s' % error)
        return 2

    deadline = time.time() + args.seconds
    seen = False
    gone_since = None
    while time.time() < deadline:
        time.sleep(1.0)
        alive = running()
        if alive:
            seen = True
            gone_since = None
        elif seen:
            gone_since = gone_since or time.time()
            if time.time() - gone_since >= 3.0:
                print('[*] 客户端已退出')
                return 0
        elif child.poll() is not None and not seen:
            # 首个子进程退出且没有新实例出现：大概率是启动失败或被单实例互斥挡回
            print('[!] 子进程已退出（exit=%s），且没有检测到 %s 在运行'
                  % (child.returncode, IMAGE))
            return child.returncode or 3

    print('[*] 到达 --seconds 上限（%.0fs）' % args.seconds)
    if args.kill and running():
        print('[*] --kill：尝试结束客户端（非管理员会失败）')
        subprocess.run(['taskkill', '/F', '/IM', IMAGE], capture_output=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
