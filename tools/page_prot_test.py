#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""方案 B：页保护存在性测试（只改页表，不改字节）

目的
----
回答「某个地址的代码到底有没有被执行过」，而且**一个字节都不改**：
Themida 的完整性校验读的是代码段字节，页表保护位不在它的视野里
（除非它专门去查 VirtualQuery 的保护属性，代价很低，所以本工具会打印退出码做区分）。

判定逻辑
--------
    VirtualProtectEx(page, PAGE_READWRITE)     # 保留读写，去掉执行位
      → 若目标进程在此页取指 → DEP 违反 → 0xC0000005
      → 若只是数据读（含 CRC 校验）→ 完全正常，无副作用
    于是：进程死 = 这一页被执行过；进程活 = 这一页没被执行。

两种"死"要分清：
    ExitCode == 0xC0000005   → DEP 违反 = 真的执行了（我们要的信号）
    ExitCode == 1 / 0xE0000001 等 → 自己的检测逻辑主动退出（信号无效，需换手段）

用法
----
    # 0) 机制自检：先证明"去执行位能杀人、且杀出来的退出码是 0xC0000005"
    #    不碰客户端，用一个 python 子进程当靶子
    python tools/page_prot_test.py --selftest

    # 1) 单页测试（页面按 4KB 对齐，0x544790 → 页 0x544000）
    python tools/page_prot_test.py --page 0x544790 --hold 40

    # 2) 多页顺序测试（每页一个独立窗口，进程一死立即停）
    python tools/page_prot_test.py --page 0x544790,0x544F60,0xA46480 --hold 25

    # 3) 只看环境（DEP 有没有生效、页面当前保护、模块基址）
    python tools/page_prot_test.py --probe-only

参数说明
----
    --mode rw      PAGE_READWRITE（默认）  读得动、执行不了 —— 本方案的正解
    --mode none    PAGE_NOACCESS           读也拦，适合"确认 DEP 没开"的退路
    --mode guard   PAGE_EXECUTE_READ|GUARD 读/执行都拦一次，然后自动解除

说明：客户端是 32 位（WOW64），但本工具用 64 位 Python 调 VirtualQueryEx，
返回的是 64 位 MEMORY_BASIC_INFORMATION（48 字节），不要用 32 位布局。
"""
from __future__ import annotations

import argparse
import ctypes
import os
import subprocess
import sys
import time
from ctypes import wintypes as w

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

# ---- 常量 ----
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
SYNCHRONIZE = 0x00100000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_GUARD = 0x100

MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000

WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
STILL_ACTIVE = 259

PROT_NAME = {
    0x00: 'PAGE_NOACCESS?', PAGE_NOACCESS: 'NOACCESS', PAGE_READONLY: 'READONLY',
    PAGE_READWRITE: 'READWRITE', 0x08: 'WRITECOPY',
    PAGE_EXECUTE: 'EXECUTE', PAGE_EXECUTE_READ: 'EXECUTE_READ',
    PAGE_EXECUTE_READWRITE: 'EXECUTE_READWRITE', 0x80: 'EXECUTE_WRITECOPY',
}


class MBI64(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', ctypes.c_ulonglong),
        ('AllocationBase', ctypes.c_ulonglong),
        ('AllocationProtect', w.DWORD),
        ('__a1', w.DWORD),
        ('RegionSize', ctypes.c_ulonglong),
        ('State', w.DWORD),
        ('Protect', w.DWORD),
        ('Type', w.DWORD),
        ('__a2', w.DWORD),
    ]


k32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
k32.OpenProcess.restype = w.HANDLE
k32.CloseHandle.argtypes = [w.HANDLE]
k32.VirtualProtectEx.argtypes = [w.HANDLE, w.LPVOID, ctypes.c_size_t, w.DWORD,
                                ctypes.POINTER(w.DWORD)]
k32.VirtualProtectEx.restype = w.BOOL
k32.VirtualQueryEx.argtypes = [w.HANDLE, w.LPCVOID, ctypes.POINTER(MBI64),
                               ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
k32.WaitForSingleObject.restype = w.DWORD
k32.GetExitCodeProcess.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
k32.GetExitCodeProcess.restype = w.BOOL
k32.GetProcessMitigationPolicy.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID,
                                          ctypes.c_size_t]
k32.GetProcessMitigationPolicy.restype = w.BOOL
psapi.EnumProcessModulesEx.argtypes = [w.HANDLE, ctypes.POINTER(w.HMODULE), w.DWORD,
                                       ctypes.POINTER(w.DWORD), w.DWORD]
psapi.EnumProcessModulesEx.restype = w.BOOL
psapi.GetModuleBaseNameW.argtypes = [w.HANDLE, w.HMODULE, ctypes.c_wchar_p, w.DWORD]
psapi.GetModuleBaseNameW.restype = w.DWORD
psapi.GetModuleInformation.argtypes = [w.HANDLE, w.HMODULE, ctypes.c_void_p, w.DWORD]
psapi.GetModuleInformation.restype = w.BOOL

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FA_LOG = os.path.join(ROOT, 'server', 'fake_auth.log')


def ts() -> str:
    return time.strftime('%H:%M:%S')


def log(msg: str) -> None:
    print(f'[{ts()}] {msg}', flush=True)


# ---------------------------------------------------------------- 基础查询
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def find_pid(exe_name: str = 'GundamOnline_CHINA.exe') -> int:
    out = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {exe_name}', '/FO', 'CSV',
                          '/NH'], capture_output=True)
    txt = out.stdout.decode('mbcs', 'replace')
    for line in txt.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[0].lower() == exe_name.lower():
            try:
                return int(parts[1])
            except ValueError:
                pass
    return 0


def open_target(pid: int, need_write: bool = True) -> int:
    mask = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE
    if need_write:
        mask |= PROCESS_VM_OPERATION
    h = k32.OpenProcess(mask, False, pid)
    if not h:
        err = ctypes.get_last_error()
        raise OSError(f'OpenProcess(pid={pid}, mask=0x{mask:x}) 失败, GetLastError={err}'
                      + ('  (87=进程已退出/不存在; 5=权限不足，需管理员)' if err in (87, 5) else ''))
    return h


def module_list(h) -> list[tuple[int, str]]:
    arr = (w.HMODULE * 2048)()
    need = w.DWORD()
    if not psapi.EnumProcessModulesEx(h, arr, ctypes.sizeof(arr), ctypes.byref(need), 0x03):
        return []
    n = need.value // ctypes.sizeof(w.HMODULE)
    buf = ctypes.create_unicode_buffer(320)
    out = []
    for i in range(n):
        psapi.GetModuleBaseNameW(h, arr[i], buf, 320)
        out.append((int(arr[i] or 0), buf.value))
    return out


def dep_policy(h) -> str:
    """DEP 是否生效。GetProcessMitigationPolicy 在部分系统上跨进程查会返 87，
    改用 NtQueryInformationProcess(ProcessExecuteFlags=34) 读执行标志位：
    ExecuteFlags bit0 = MEM_EXECUTE_OPTION_DISABLE → 该进程 DEP 生效。"""
    val = w.DWORD(0)
    if k32.GetProcessMitigationPolicy(h, 0, ctypes.byref(val), ctypes.sizeof(val)):
        return f'{"ON" if val.value & 1 else "OFF"} (mitigation raw=0x{val.value:x})'
    # 退路：NtQueryInformationProcess
    ntdll = ctypes.WinDLL('ntdll')
    flags = ctypes.c_ulong(0)
    ret_len = ctypes.c_ulong(0)
    st = ntdll.NtQueryInformationProcess(w.HANDLE(h), 34, ctypes.byref(flags),
                                         ctypes.sizeof(flags), ctypes.byref(ret_len))
    if st == 0:
        on = bool(flags.value & 1)
        return f'{"ON" if on else "OFF"} (ExecuteFlags=0x{flags.value:x})'
    return f'查询失败 (NTSTATUS=0x{st & 0xFFFFFFFF:x})'


def query_page(h, page: int) -> MBI64:
    mbi = MBI64()
    got = k32.VirtualQueryEx(h, ctypes.c_void_p(page), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if not got:
        raise OSError(f'VirtualQueryEx(0x{page:x}) 失败 err={ctypes.get_last_error()}')
    return mbi


def describe(mbi: MBI64) -> str:
    p = mbi.Protect
    name = PROT_NAME.get(p & 0xFF, f'0x{p:x}')
    guard = '|GUARD' if p & PAGE_GUARD else ''
    kind = {MEM_IMAGE: 'IMAGE', 0x20000: 'PRIVATE', 0x40000: 'MAPPED'}.get(mbi.Type, str(mbi.Type))
    return (f'base=0x{mbi.BaseAddress:x} size=0x{mbi.RegionSize:x} '
            f'protect={name}{guard} type={kind}')


def set_protect(h, page: int, newprot: int) -> int:
    old = w.DWORD(0)
    if not k32.VirtualProtectEx(h, ctypes.c_void_p(page), 0x1000, newprot, ctypes.byref(old)):
        raise OSError(f'VirtualProtectEx(0x{page:x}) 失败 err={ctypes.get_last_error()}')
    return old.value


def exit_code(h) -> int | None:
    code = w.DWORD(0)
    if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
        return None
    return None if code.value == STILL_ACTIVE else code.value


def tail_fa(n: int = 3) -> list[str]:
    """fake_auth.log 最后几行 —— 用来对死亡时刻在服务第几张表。"""
    try:
        with open(FA_LOG, 'r', encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
        return [ln.rstrip() for ln in lines[-n:]]
    except Exception:
        return []


def last_table_no() -> str:
    """从 fake_auth.log 里抠出「本轮第 N 张」。"""
    try:
        with open(FA_LOG, 'r', encoding='utf-8', errors='replace') as fh:
            txt = fh.read()
    except Exception:
        return '?'
    n = None
    for part in txt.split('本轮第'):
        seg = part.strip().split('张')[0].strip()
        if seg.isdigit():
            n = seg
    return n or '?'


# ---------------------------------------------------------------- 核心测试
def _probe_default(h):
    """退路：靠 GetExitCodeProcess 轮询存活。"""
    return lambda: exit_code(h) is None


def test_page(h, page: int, hold: int, mode: str, restore: bool = True,
              probe=None) -> str:
    """返回 'alive' / 'dead' / 'dead?dep' 等判定。"""
    page &= ~0xFFF
    newprot = {'rw': PAGE_READWRITE, 'none': PAGE_NOACCESS,
               'guard': PAGE_EXECUTE_READ | PAGE_GUARD}[mode]

    mbi = query_page(h, page)
    log(f'页 0x{page:x} 当前：{describe(mbi)}')
    if mbi.State != MEM_COMMIT:
        log('  !! 该页未提交，跳过')
        return 'skip'

    old = set_protect(h, page, newprot)
    log(f'  已改为 {PROT_NAME.get(newprot & 0xFF, hex(newprot))}'
        f'{"|GUARD" if newprot & PAGE_GUARD else ""}（原 {PROT_NAME.get(old & 0xFF, hex(old))}）'
        f'  —— 字节未改，仅页表')
    chk = query_page(h, page)
    log(f'  回读确认：{describe(chk)}')

    t0 = time.time()
    verdict = 'alive'
    while True:
        left = hold - (time.time() - t0)
        if left <= 0:
            break
        # probe 优先（本地 Popen 对象最可靠）；否则用 WaitForSingleObject
        if probe is not None:
            if not probe():
                code = exit_code(h)
                el = time.time() - t0
                verdict = 'dead'
                log(f'  >>> 进程在 {el:.1f}s 后死亡（由 probe 判定），'
                    f'ExitCode={code if code is None else hex(code)}')
                log(f'      死亡时「本轮第 {last_table_no()} 张」')
                for ln in tail_fa(3):
                    log(f'      fa| {ln}')
                if code == 0xC0000005:
                    log('  >>> 0xC0000005 = 访问违例 → 该页被作为代码执行过（DEP 拦下）')
                    verdict = 'dead_dep'
                elif code == 0xC000001D:
                    verdict = 'dead_ill'
                else:
                    log('  >>> 不是 DEP 违例 → 更可能是保护层自己发现页属性被改并主动退出，'
                        '这一页的结论无效')
                    verdict = 'dead_other'
                break
            time.sleep(0.4)
        else:
            r = k32.WaitForSingleObject(h, int(min(left, 1.0) * 1000))
            if r == WAIT_OBJECT_0:
                code = exit_code(h)
                el = time.time() - t0
                verdict = 'dead'
                log(f'  >>> 进程在 {el:.1f}s 后死亡，ExitCode={code if code is None else hex(code)}')
                log(f'      死亡时「本轮第 {last_table_no()} 张」')
                for ln in tail_fa(3):
                    log(f'      fa| {ln}')
                if code == 0xC0000005:
                    log('  >>> 0xC0000005 = 访问违例 → 该页被作为代码执行过（DEP 拦下）')
                    verdict = 'dead_dep'
                elif code == 0xC000001D:
                    verdict = 'dead_ill'
                else:
                    log('  >>> 不是 DEP 违例 → 更可能是保护层自己发现页属性被改并主动退出，'
                        '这一页的结论无效')
                    verdict = 'dead_other'
                break
            if r == 0xFFFFFFFF:
                # 句柄没有 SYNCHRONIZE 或被沙箱拦掉 —— 不能当成"活着"
                log(f'  !! WaitForSingleObject 失败 err={ctypes.get_last_error()}，'
                    '改用轮询 OpenProcess 判断存活')
                probe = _probe_default(h)
                continue
        # 每 5 秒报一次进度
        el = time.time() - t0
        if int(el) and int(el) % 5 == 0 and abs(el - round(el)) < 0.3:
            log(f'  .. 存活 {el:.0f}s（当前服务第 {last_table_no()} 张）')
    else:
        pass

    if verdict == 'alive':
        log(f'  >>> 存活 {hold}s 未死 → 该页在观察窗口内没有被执行')
        if restore:
            try:
                set_protect(h, page, old)
                log(f'  已恢复原保护 {PROT_NAME.get(old & 0xFF, hex(old))}')
            except OSError as e:
                log(f'  !! 恢复失败：{e}')
    return verdict


# ---------------------------------------------------------------- 自检
def selftest(hold: int = 6, mode: str = 'rw') -> int:
    """用 python 子进程当靶子，验证「去执行位 → DEP 杀 → 0xC0000005」。"""
    log('自检：起一个 python 子进程，让它死循环调 time.sleep（即压 kernel32 的跳转桩页）')
    # 关键：让子进程**自己报出**它每轮真正执行的地址，不靠猜偏移。
    # （踩过的坑：python 3.13 的 time.sleep 走 api-ms-win-core-synch，压根不碰
    #   旧式 kernel32!Sleep 桩页，导致上一版自检"存活=未执行"的假阴性。）
    src = (
        "import ctypes, sys\n"
        "k = ctypes.WinDLL('KernelBase.dll')\n"
        "f = ctypes.cast(k.Sleep, ctypes.c_void_p).value\n"
        "sys.stdout.write(hex(f) + '\\n'); sys.stdout.flush()\n"
        "while True:\n"
        "    k.Sleep(1)\n"
    )
    child = subprocess.Popen([sys.executable, '-c', src], stdout=subprocess.PIPE,
                             text=True, bufsize=1)

    def bye(code):
        try:
            if child.poll() is None:
                child.kill()
        except Exception:
            pass
        return code

    try:
        line = child.stdout.readline().strip()
        target = int(line, 16)
        log(f'子进程报出执行地址 = 0x{target:x}，页 0x{target & ~0xFFF:x}')

        h = open_target(child.pid)
        log(f'子进程 pid={child.pid}  DEP={dep_policy(h)}')

        v = test_page(h, target, hold, mode, restore=True,
                      probe=lambda: child.poll() is None)
        if v == 'dead_dep':
            log('自检通过：机制可用（去执行位 → 0xC0000005）')
            return bye(0)
        log(f'自检未达预期（verdict={v}）')
        return bye(3)
    finally:
        try:
            if child.poll() is None:
                child.kill()
        except Exception:
            pass


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description='方案 B：页保护存在性测试')
    ap.add_argument('--pid', type=int, default=0, help='目标 PID，0=自动找客户端')
    ap.add_argument('--page', default='', help='目标 VA，可逗号分隔多个')
    ap.add_argument('--hold', type=int, default=40, help='每页观察秒数')
    ap.add_argument('--mode', default='rw', choices=['rw', 'none', 'guard'])
    ap.add_argument('--probe-only', action='store_true', help='只打印环境与页面保护，不改')
    ap.add_argument('--selftest', action='store_true', help='用子进程自检机制')
    ap.add_argument('--selftest-mode', default='rw', choices=['rw', 'none', 'guard'],
                    help='自检时用哪种保护（none 可区分"根本没碰这页"与"读了但没执行"）')
    ap.add_argument('--no-restore', action='store_true', help='存活时不恢复保护')
    args = ap.parse_args()

    log(f'管理员：{is_admin()}')

    # 自检打的是自己起的同权限子进程，不需要提权 —— 先跑，方便快速验证机制。
    if args.selftest:
        return selftest(hold=min(args.hold, 15), mode=args.selftest_mode)

    if not is_admin():
        log('!! 不是管理员。客户端是提权起的，本工具也必须提权，否则 OpenProcess 会被拒。')
        return 5

    if not args.page:
        log('!! 需要 --page（或 --selftest）')
        return 2

    pid = args.pid or find_pid()
    if not pid:
        log('!! 没找到 GundamOnline_CHINA.exe')
        return 4
    log(f'目标 pid={pid}')

    try:
        h = open_target(pid, need_write=not args.probe_only)
    except OSError as e:
        log(f'!! {e}')
        return 6

    try:
        log(f'DEP 策略：{dep_policy(h)}')
        mods = module_list(h)
        if mods:
            log(f'主模块 base=0x{mods[0][0]:x} ({mods[0][1]})，共 {len(mods)} 个模块')
        pages = [int(x, 0) for x in args.page.replace(';', ',').split(',') if x.strip()]
        for va in pages:
            mbi = query_page(h, va & ~0xFFF)
            log(f'0x{va:x} → 页 0x{va & ~0xFFF:x}：{describe(mbi)}')
            if args.probe_only:
                continue
            v = test_page(h, va, args.hold, args.mode, restore=not args.no_restore)
            log(f'0x{va:x} 判定 = {v}')
            if v.startswith('dead'):
                log('进程已死，后续页不再测')
                break
    finally:
        k32.CloseHandle(h)
    return 0


if __name__ == '__main__':
    sys.exit(main())
