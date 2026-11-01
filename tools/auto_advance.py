#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""自动推进器：等表阶段跑完，自动把下载器计数写成 0，让状态机进入「正在取得机师数据」。

为什么要它
----------
序号 67 那张表（`develop/mechanic_overcustom.csv`，`CMechanicOverCustomTable`）在
本版本客户端里始终走不到成功路径 ⇒ 下载器不会被析构 ⇒ 步骤机 `FUN_0043b530` 的
case 5（`if ([game+0x580] == 0)`）永远等不到。

实测可以把下载器对象里的「剩余张数」（`+0x0C`）直接写 0，tick 就会走 done 分支：
析构 + `[game+0x580] = 0` → case 5 通过 → case 6/7 → 客户端发出 `0x60CD`
（send_pilot_list_get），界面变成「正在取得机师数据」。

这是**把已知的死锁自动化绕过**，不是修复。序号 67 为什么失败仍未查明。

用法
----
由 `tools/start_local.cmd` 以管理员身份拉起（必须在管理员下跑，否则 OpenProcess 被拒）：

    python tools/auto_advance.py            # 常驻，等每一轮
    python tools/auto_advance.py --once     # 只处理一轮就退出

日志：`server/hook_runs/_auto_advance.log`
"""
from __future__ import annotations

import argparse
import ctypes
import os
import re
import subprocess
import sys
import time
from ctypes import wintypes as w

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FA_LOG = os.path.join(ROOT, 'server', 'fake_auth.log')
OUT_LOG = os.path.join(ROOT, 'server', 'hook_runs', '_auto_advance.log')

k32 = ctypes.WinDLL('kernel32', use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008

DL_VTABLE = 0xCB9EDC      # CDataTableDownload
OFF_REMAIN = 0x0C         # 剩余张数；==0 即"下载完成"

k32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
k32.OpenProcess.restype = w.HANDLE
k32.CloseHandle.argtypes = [w.HANDLE]
k32.ReadProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = w.BOOL
k32.WriteProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = w.BOOL
k32.VirtualQueryEx.argtypes = [w.HANDLE, w.LPCVOID, ctypes.c_void_p, ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t


class MBI(ctypes.Structure):
    _fields_ = [('Base', ctypes.c_ulonglong), ('Alloc', ctypes.c_ulonglong),
                ('AllocProt', w.DWORD), ('a1', w.DWORD),
                ('Size', ctypes.c_ulonglong), ('State', w.DWORD),
                ('Protect', w.DWORD), ('Type', w.DWORD), ('a2', w.DWORD)]


def log(msg: str) -> None:
    line = '%s  %s' % (time.strftime('%H:%M:%S'), msg)
    print(line, flush=True)
    try:
        os.makedirs(os.path.dirname(OUT_LOG), exist_ok=True)
        with open(OUT_LOG, 'a', encoding='utf-8') as fh:
            fh.write(line + '\n')
    except Exception:
        pass


def find_pid(exe='GundamOnline_CHINA.exe') -> int:
    out = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {exe}', '/FO', 'CSV', '/NH'],
                         capture_output=True)
    for line in out.stdout.decode('mbcs', 'replace').splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[0].lower() == exe.lower():
            try:
                return int(parts[1])
            except ValueError:
                pass
    return 0


def read_u32(h, addr):
    buf = ctypes.create_string_buffer(4)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, 4, ctypes.byref(got)):
        return None
    return int.from_bytes(buf.raw[:4], 'little')


def write_u32(h, addr, val) -> bool:
    buf = (val & 0xFFFFFFFF).to_bytes(4, 'little')
    got = ctypes.c_size_t(0)
    return bool(k32.WriteProcessMemory(h, ctypes.c_void_p(addr), buf, 4, ctypes.byref(got))) and got.value == 4


def find_downloader(h, limit_mb=1500):
    """在目标进程里找 vtable == 0xCB9EDC 的对象（CDataTableDownload）。"""
    pat = DL_VTABLE.to_bytes(4, 'little')
    cur = 0
    total = 0
    mbi = MBI()
    step = 0x10000
    buf = ctypes.create_string_buffer(step)
    while cur < 0x7FFFFFFF and total < limit_mb * 1024 * 1024:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(cur), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base, size, state, prot = mbi.Base, mbi.Size, mbi.State, mbi.Protect
        if state == 0x1000 and prot in (0x04, 0x40, 0x02, 0x20, 0x80):
            off = 0
            while off < size:
                n = min(step, size - off)
                got = ctypes.c_size_t(0)
                if k32.ReadProcessMemory(h, ctypes.c_void_p(base + off), buf, n, ctypes.byref(got)) and got.value:
                    chunk = buf.raw[:got.value]
                    total += got.value
                    i = chunk.find(pat)
                    while i >= 0:
                        yield base + off + i
                        i = chunk.find(pat, i + 4)
                off += step
        cur = base + size


def wait_for_round(nth=65, timeout=600.0, poll=0.4):
    """等 fake_auth.log **新写入**的内容里出现「本轮第 Nth 张」。

    必须从启动时记录的偏移开始读：日志里历史轮次本来就有那一行，
    只扫尾部 20KB 会立刻误判（实测因此把客户端在表阶段就搞崩了）。
    """
    try:
        start = os.path.getsize(FA_LOG)
    except OSError:
        start = 0
    log('从日志偏移 %d 开始监听（忽略此前全部历史）' % start)
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with open(FA_LOG, 'rb') as fh:
                fh.seek(start)
                chunk = fh.read()
            tail = chunk.decode('utf-8', 'replace')
        except Exception:
            tail = ''
        if re.search(r'本轮第 %d 张' % nth, tail):
            return True
        time.sleep(poll)
    return False


def advance_once(nth: int, settle: float, timeout: float, now: bool = False) -> str:
    if now:
        log('--now：不等新一轮日志，直接推当前这一轮')
    elif not wait_for_round(nth, timeout):
        return 'timeout'
    else:
        log('检测到本轮第 %d 张，准备推进' % nth)
    time.sleep(settle)

    pid = find_pid()
    if not pid:
        log('[!] 客户端没在跑')
        return 'noproc'
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE
                        | PROCESS_VM_OPERATION, False, pid)
    if not h:
        log('[!] OpenProcess 失败 err=%d（需要管理员）' % ctypes.get_last_error())
        return 'noaccess'
    try:
        hit = None
        for obj in find_downloader(h):
            remain = read_u32(h, obj + OFF_REMAIN)
            if remain is None or remain > 0x1000:
                continue        # 代码段里的常量命中，不是真对象
            hit = (obj, remain)
            break
        if not hit:
            log('[!] 没找到下载器对象（可能已经过了这一步）')
            return 'noobj'
        obj, remain = hit
        log('下载器 @0x%x，剩余=%d' % (obj, remain))
        if remain == 0:
            log('已经是 0，不用动')
            return 'already'
        if write_u32(h, obj + OFF_REMAIN, 0):
            log('已把 +0x0C 写成 0（%d -> 0），等客户端发 0x60CD' % remain)
            return 'ok'
        log('[!] 写失败 err=%d' % ctypes.get_last_error())
        return 'writefail'
    finally:
        k32.CloseHandle(h)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--once', action='store_true', help='只处理一轮')
    ap.add_argument('--nth', type=int, default=65, help='本轮第几张之后推进（默认 65）')
    ap.add_argument('--settle', type=float, default=1.5, help='检测到后等几秒再写')
    ap.add_argument('--timeout', type=float, default=600, help='单轮等待上限秒')
    ap.add_argument('--now', action='store_true',
                    help='不等"本轮第 N 张"这条新日志，立刻对当前状态推一次（客户端已经卡住时用）')
    args = ap.parse_args()

    if not ctypes.windll.shell32.IsUserAnAdmin():
        # 同用户进程本来就不需要管理员；真打不开时 advance_once 会报 noaccess。
        log('[i] 当前不是管理员：若客户端是同用户启动，OpenProcess 仍然可行，继续')

    log('==== auto_advance 启动 nth=%d settle=%.1fs once=%s now=%s ===='
        % (args.nth, args.settle, args.once, args.now))
    while True:
        r = advance_once(args.nth, args.settle, args.timeout, now=args.now)
        log('本轮结果: %s' % r)
        if args.once:
            return 0
        time.sleep(3)


if __name__ == '__main__':
    sys.exit(main())
