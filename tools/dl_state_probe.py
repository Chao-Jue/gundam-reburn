#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""只读探针：读「数据表下载器」的三/四个整数，判定它到底处于哪个状态。

**绝不写目标进程**：只 OpenProcess(PROCESS_QUERY_INFORMATION|VM_READ) + ReadProcessMemory，
读完立刻 CloseHandle。不注入、不改字节、不 attach 调试器。

判据（来自 server/数据表下载-发送循环与结束条件.md §6）：

    session   = [0x117D380]          # 0x7A60 字节的会话对象（vtable 应为 0xE14D04）
    downloader= [session+0x580]

    - downloader == 0                -> tick 第⑤步已跑过：下载器已析构并置空
    - downloader != 0 且 +0x0C == 0  -> 卡在「刚重建还没置 1」（静默失败，B）
    - downloader != 0 且 +0x0C != 0  -> 两条都不成立，转查 tick 为什么没被调用

用法：
    python tools/dl_state_probe.py --pid 4732
    python tools/dl_state_probe.py --pid-name GundamOnline_CHINA.exe
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as w
import sys

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

GLOBAL_SESSION = 0x0117D380          # 指向 0x7A60 字节会话对象
OFF_DOWNLOADER = 0x580
VT_CGVOPROTOLOUNGE = 0x00E14D04

# 表加载分派用的表对象全局（0x544E3C 跳转表里读出来的）
TABLE_GLOBALS = {
    0x01169A48: "case 0x01 MSMA_WEAPONSET (工作正常)",
    0x01169A04: "case 0x43 OVER_CUSTOM_DEVELOP (卡在这里)",
    0x01169AA0: "case 0x44",
    0x01169AA4: "case 0x45",
}

k32.OpenProcess.restype = w.HANDLE
k32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
k32.ReadProcessMemory.restype = w.BOOL
k32.ReadProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.CloseHandle.argtypes = [w.HANDLE]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD), ("th32ProcessID", w.DWORD),
                ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", w.DWORD),
                ("cntThreads", w.DWORD), ("th32ParentProcessID", w.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", w.DWORD),
                ("szExeFile", w.WCHAR * 260)]


def find_pid(name: str) -> int:
    TH32CS_SNAPPROCESS = 2
    k32.CreateToolhelp32Snapshot.restype = w.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
    k32.Process32FirstW.argtypes = [w.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k32.Process32NextW.argtypes = [w.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    e = PROCESSENTRY32W()
    e.dwSize = ctypes.sizeof(e)
    if k32.Process32FirstW(snap, ctypes.byref(e)):
        while True:
            if e.szExeFile.lower() == name.lower():
                pid = int(e.th32ProcessID)
                break
            if not k32.Process32NextW(snap, ctypes.byref(e)):
                pid = 0
                break
        k32.CloseHandle(snap)
        return pid
    k32.CloseHandle(snap)
    return 0


def walk_wstring_map(rd, head_ptr):
    """遍历 MSVC std::map<wstring, _>：_Myhead 节点 +0x00 _Left / +0x04 _Parent /
    +0x08 _Right / +0x0D _Isnil；键是 +0x10 起的 std::wstring。返回名字列表。"""
    out, seen = [], set()

    def isnil(node):
        return bool(rd(node + 0x0D, 1) & 0xFF)

    def key_of(node):
        size = rd(node + 0x20)
        cap = rd(node + 0x24)
        if not (0 < size < 512):
            return None
        if cap > 8:                      # 堆上
            p = rd(node + 0x10)
            raw = rd(p, size * 2)
        else:                            # SSO
            raw = rd(node + 0x10, size * 2)
        try:
            return raw.to_bytes(size * 2, "little").decode("utf-16-le")
        except Exception:                # noqa: BLE001
            return None

    def walk(node):
        if not node or node in seen or len(seen) > 500:
            return
        seen.add(node)
        if isnil(node):
            return
        left, right = rd(node), rd(node + 0x08)
        walk(left)
        k = key_of(node)
        if k:
            out.append(k)
        walk(right)

    walk(rd(head_ptr))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--pid-name", default="GundamOnline_CHINA.exe")
    ap.add_argument("--map", action="store_true",
                    help="把下载队列里剩下的文件名也读出来（遍历 std::map）")
    a = ap.parse_args()

    pid = a.pid or find_pid(a.pid_name)
    if not pid:
        print(f"[!] 找不到进程 {a.pid_name}")
        return 2
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        print(f"[!] OpenProcess 失败 WinError={ctypes.get_last_error()}")
        return 3

    def rd(addr, n=4):
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)) \
                or got.value != n:
            raise OSError(f"读 0x{addr:08X} 失败 WinError={ctypes.get_last_error()}")
        return int.from_bytes(buf.raw, "little")

    try:
        print(f"[*] pid={pid}")
        sess = rd(GLOBAL_SESSION)
        print(f"    [0x{GLOBAL_SESSION:08X}] session = 0x{sess:08X}")
        if sess == 0:
            print("[!] 会话对象指针为空 —— 还没建会话，或已经销毁")
            return 0
        vt = rd(sess)
        tag = "OK 就是 CGVOProtoLounge" if vt == VT_CGVOPROTOLOUNGE else "★ 不是预期类 ★"
        print(f"    session.vtable = 0x{vt:08X}   {tag}")

        dl = rd(sess + OFF_DOWNLOADER)
        print(f"    [session+0x{OFF_DOWNLOADER:X}] downloader = 0x{dl:08X}")
        if dl == 0:
            print("[结论] downloader == 0  ⇒ tick 第⑤步已跑过：下载器已析构并置空。")
            print("        ⇒ 步骤机 case 5 的 `[game+0x580]==0` 应为真。")
            return 0

        f08, f0c, f10 = rd(dl + 0x08), rd(dl + 0x0C), rd(dl + 0x10)
        print(f"    downloader+0x08 = 0x{f08:08X}  (map 哨兵)")
        print(f"    downloader+0x0C = 0x{f0c:08X}  (就绪/待发标志)")
        print(f"    downloader+0x10 = 0x{f10:08X}  (flags，bit0 = 有下一张)")
        dvt = rd(dl)
        print(f"    downloader.vtable = 0x{dvt:08X}  (应为 0x00CB9EDC)")
        if f0c == 0:
            print("[结论] +0x0C == 0 ⇒ 卡在「刚重建还没置 1」（B：静默失败）。")
            print("        ⇒ 下载器下一帧就会被判完成并销毁，但当前还活着。")
        else:
            print(f"[结论] +0x0C == {f0c} ⇒ 队列里还剩 {f0c} 张，客户端没有继续发请求。")
            print("        ⇒ A/B 两条都不成立，卡在「上一张的回复处理没走完」。")

        print()
        if a.map:
            print("[*] 队列里剩下的文件名（std::map<wstring,_>，_Myhead = downloader+0x08）")
            try:
                for name in walk_wstring_map(rd, f08):
                    print(f"    {name}")
            except Exception as e:                      # noqa: BLE001
                print(f"    遍历失败: {e}")

        print()
        print("[*] 表对象全局（NULL ⇒ case 里 mov eax,[ecx] 会直接 AV，与正文内容无关）")
        for gva, desc in TABLE_GLOBALS.items():
            try:
                p = rd(gva)
            except OSError as e:
                print(f"    0x{gva:08X}  读取失败: {e}")
                continue
            if p == 0:
                print(f"    0x{gva:08X} = NULL   ★ {desc}")
            else:
                try:
                    vt = rd(p)
                    print(f"    0x{gva:08X} = 0x{p:08X}  vtable=0x{vt:08X}   {desc}")
                except OSError:
                    print(f"    0x{gva:08X} = 0x{p:08X}  (vtable 读不到)   {desc}")
        return 0
    finally:
        k32.CloseHandle(h)


if __name__ == "__main__":
    sys.exit(main())
