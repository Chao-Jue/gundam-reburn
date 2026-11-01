#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""只读探针：机师阶段的关键状态。

零写入、零注入：只 OpenProcess + ReadProcessMemory，不写任何字节、
不改代码、不挂 hook，CPS 的代码自检看不到差异。

读的内容（VA 全部来自 server/img_dump/main_GundamOnline_CHINA.exe，镜像基址 0x400000）：

  0x117D380  CGVOProtoLounge 全局单例指针
     +0x00   vtable（应为 0x00E14D04）
     +0x29E  recv 期望位数组（flag[code]），0xE13A 的 code = 0x0C
     +0x4E0  配额块数组，每 48 字节一块，0xE13A 是第 0x0C 块
     +0x740  ★ 0xE13A 成功回调计数器（0xAD032D: add dword [esi+0x740],1）
     +0x744  同上高 32 位
     +0x1670 0x1D02 大厅成员列表成功回调计数器
              （反编译器显示 uint* 索引 0x59C，真实字节偏移 = 0x59C * 4）
     +0x16A0 0xA64A 大厅脚本成功回调计数器
              （反编译器显示 uint* 索引 0x5A8，真实字节偏移 = 0x5A8 * 4）

  0x1161F28  游戏对象（DAT_01161f28）
     +0x574   大厅初始化步骤（最终应到 0x14）
     +0x578   各初始化应答完成位
     +0x10615 步骤机 case 8 等的标志（0x4392BD 置 1）
     +0x10611 忙标志
     +0x10613 大厅初始化末段标志
     +0x10619 bmg 列表非空标志
     +0x105A0 回归活动处理状态（正常路径必须为 0）
     +0x580   数据表下载泵（非 0 = case 5 还在等）
     +0x544   大厅初始化任务句柄（case 0x14 完成后清零）
     +0x1061C 等待窗对象（不是当前场景）
     +0x10628..+0x1062C 场景切换阻塞项 vector；大厅初始化移除编号 0x0D

  0x1169A04  develop/mechanic_overcustom 表对象（卡住那张）

用法：
  python tools/probe_pilot_state.py                 # 每秒一次，直到进程退出
  python tools/probe_pilot_state.py --seconds 600
  python tools/probe_pilot_state.py --file server/pilot_state.log

判读：
  [E13A] cnt 在收到 0xE13A 之后 +1   ⇒ handler 走到了成功回调 ⇒ 问题在回调之后
  [E13A] cnt 一直不变                ⇒ handler 没执行 ⇒ 投递/闸门/读取失败
"""
from __future__ import annotations

import argparse
import ctypes
import os
import struct
import sys
import time
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_char * 260),
    ]


def find_pid(name: str):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        return None
    try:
        e = PROCESSENTRY32()
        e.dwSize = ctypes.sizeof(PROCESSENTRY32)
        ok = k32.Process32First(snap, ctypes.byref(e))
        while ok:
            if e.szExeFile.decode("mbcs", "replace").lower() == name.lower():
                return e.th32ProcessID
            ok = k32.Process32Next(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return None


class Reader:
    def __init__(self, pid: int):
        self.h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
        if not self.h:
            raise OSError(ctypes.get_last_error(), "OpenProcess 失败（需要管理员权限）")
        self.pid = pid

    def read(self, va: int, n: int):
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(self.h, ctypes.c_void_p(va), buf, n, ctypes.byref(got))
        if not ok or got.value != n:
            return None
        return buf.raw

    def u8(self, va):
        b = self.read(va, 1)
        return None if b is None else b[0]

    def u16(self, va):
        b = self.read(va, 2)
        return None if b is None else int.from_bytes(b, "little")

    def u32(self, va):
        b = self.read(va, 4)
        return None if b is None else int.from_bytes(b, "little")

    def u64(self, va):
        b = self.read(va, 8)
        return None if b is None else int.from_bytes(b, "little")

    def close(self):
        if self.h:
            k32.CloseHandle(self.h)
            self.h = None


G_PROTO = 0x117D380
G_GAME = 0x1161F28
G_SCENE_MANAGER = 0x1161F7C
G_TBL_MECHANIC = 0x1169A04
E13A_CODE = 0x0C


def snapshot(r: Reader) -> dict:
    d = {}
    proto = r.u32(G_PROTO) or 0
    d["proto"] = proto
    if proto:
        d["proto_vt"] = r.u32(proto) or 0
        d["flag_c"] = r.u8(proto + 0x29E + E13A_CODE)
        blk = proto + 0x4E0 + 48 * E13A_CODE
        d["blk"] = (r.u32(blk), r.u32(blk + 4), r.u32(blk + 8), r.u32(blk + 0xC),
                    r.u32(blk + 0x10), r.u32(blk + 0x14))
        d["e13a_cnt"] = r.u64(proto + 0x740) or 0
        d["members_1d02_cnt"] = r.u32(proto + 0x1670) or 0
        d["script_a64a_cnt"] = r.u32(proto + 0x16A0) or 0
        d["msma_add_cnt"] = r.u32(proto + 0x2960)
        d["send_flag_64"] = r.u8(proto + 0x64)
        d["send_flag_67"] = r.u8(proto + 0x67)
        # 0xBD1610 收完一帧会 `mov edx,[esi+0x50]` 再清 `[edx+0x24]`：
        # +0x50 = 当前挂起请求对象；+0x0C = handler 建游标用的“当前消息对象”。
        d["pending"] = r.u32(proto + 0x50)
        d["msg_obj"] = r.u32(proto + 0x0C)
        if d["pending"]:
            d["pending_vt"] = r.u32(d["pending"])
            d["pending_24"] = r.u32(d["pending"] + 0x24)
        if d["msg_obj"]:
            d["msg_vt"] = r.u32(d["msg_obj"])
            d["msgq"] = tuple(r.u32(d["msg_obj"] + 4 * i) for i in range(24))
    game = r.u32(G_GAME) or 0
    d["game"] = game
    if game:
        d["game_state"] = r.u32(game)
        d["mission_ready"] = r.u8(game + 0x312B0)
        d["hall_step"] = r.u32(game + 0x574)
        d["hall_flags"] = r.u32(game + 0x578)
        d["comeback_state"] = r.u32(game + 0x105A0)
        d["g10615"] = r.u8(game + 0x10615)
        d["g10611"] = r.u8(game + 0x10611)
        d["g10613"] = r.u8(game + 0x10613)
        d["g10619"] = r.u8(game + 0x10619)
        d["hall_task"] = r.u32(game + 0x544)
        d["game_plus4"] = r.u32(game + 4)
        d["tuto_step"] = r.u32(game + 0x105E8)
        waiting = r.u32(game + 0x1061C) or 0
        d["waiting_window"] = waiting
        d["wait_state"] = r.u32(waiting + 0x164) if waiting else None
        blockers_begin = r.u32(game + 0x10628) or 0
        blockers_end = r.u32(game + 0x1062C) or 0
        d["blockers_span"] = (blockers_begin, blockers_end)
        if blockers_begin and blockers_end >= blockers_begin:
            count = min((blockers_end - blockers_begin) // 4, 32)
            d["blockers"] = tuple(r.u32(blockers_begin + 4 * i) for i in range(count))
        else:
            d["blockers"] = ()
        pump = r.u32(game + 0x580) or 0
        d["pump"] = pump
        if pump:
            d["pump_08"] = r.u32(pump + 0x08)
            d["pump_0c"] = r.u32(pump + 0x0C)
            d["pump_10"] = r.u32(pump + 0x10)
    manager = r.u32(G_SCENE_MANAGER) or 0
    d["scene_manager"] = manager
    if manager:
        # CGameSceneMgr: +4 object, +8 current, +C requested, +10 previous.
        scene = r.u32(manager + 4) or 0
        d["scene"] = scene
        d["scene_vt"] = r.u32(scene) if scene else None
        d["scene_words"] = tuple(r.u32(scene + 4 * i) for i in range(1, 9)) if scene else ()
        task_ref = r.u32(scene + 8) if scene else 0
        scene_task = r.u32(task_ref) if task_ref else 0
        d["scene_task"] = scene_task
        d["scene_task_step"] = r.u32(scene_task + 4) if scene_task else None
        d["scene_id"] = r.u32(manager + 8)
        d["scene_requested"] = r.u32(manager + 12)
        d["scene_previous"] = r.u32(manager + 16)
    tbl = r.u32(G_TBL_MECHANIC) or 0
    d["mech_tbl"] = tbl
    if tbl:
        d["mech_vt"] = r.u32(tbl) or 0
        d["mech_rows"] = r.u32(tbl + 0x0C)
    # Current CCharaParamTable map, from 0x431D30. Read only the test key.
    msma_table = r.u32(0x1161F94) or 0
    if msma_table:
        d["msma_definition_count"] = r.u32(msma_table + 0x0C)
        head = r.u32(msma_table + 8) or 0
        node = r.u32(head + 4) if head else 0
        for _ in range(64):
            if not node or r.u8(node + 0x341) != 0:
                break
            key = r.u32(node + 0x10)
            if key is None:
                break
            if key == 777001:
                d["gm_definition_id"] = r.u32(node + 0x18)
                d["gm_definition_model"] = r.u32(node + 0x1C)
                # Finalized values written by native 0x54E2F0, not CSV references.
                value = node + 0x18
                for name, offset in (("hp", 0x94), ("cost", 0xE0), ("payload", 0xE8),
                                     ("respawn", 0xB0), ("warp", 0xDC)):
                    d["gm_final_" + name] = r.u32(value + offset)
                for name, offset in (("charge", 0xA0), ("move", 0xA4)):
                    raw = r.u32(value + offset)
                    d["gm_final_" + name] = (struct.unpack('<f', struct.pack('<I', raw))[0]
                                             if raw is not None else None)
                break
            node = r.u32(node + (0 if 777001 < key else 8))
    return d


def _q(t):
    if not t:
        return "-"
    return "(" + ",".join("-" if v is None else "%08X" % v for v in t) + ")"


def _hx(v):
    return "-" if v is None else "0x%08X" % v


def fmt(d: dict) -> str:
    parts = []
    parts.append("gm_final hp=%s cost=%s payload=%s respawn=%s warp=%s charge=%s move=%s"
                 % tuple(d.get("gm_final_" + name) for name in
                         ("hp", "cost", "payload", "respawn", "warp", "charge", "move")))
    parts.append("msma_add=%s definitions=%s gm_id=%s gm_model=%s"
                 % (d.get("msma_add_cnt"), d.get("msma_definition_count"),
                    d.get("gm_definition_id"), d.get("gm_definition_model")))
    if d.get("proto"):
        parts.append("proto=0x%08X vt=0x%08X flag[0xC]=%s "
                     "cnt_e13a=%d cnt_1d02=%d cnt_a64a=%d send64=%s send67=%s"
                     % (d["proto"], d.get("proto_vt", 0), d.get("flag_c"),
                        d.get("e13a_cnt", 0), d.get("members_1d02_cnt", 0),
                        d.get("script_a64a_cnt", 0),
                        d.get("send_flag_64"), d.get("send_flag_67")))
        b = d.get("blk") or (None,) * 6
        parts.append("gate_block=%s" % (b,))
        parts.append("  pending=0x%08X(vt=%s +24=%s)"
                     % (d.get("pending") or 0, _hx(d.get("pending_vt")),
                        _hx(d.get("pending_24"))))
        parts.append("  msg_obj=0x%08X vt=%s q=%s"
                     % (d.get("msg_obj") or 0, _hx(d.get("msg_vt")),
                        _q(d.get("msgq"))))
    else:
        parts.append("proto=NULL")
    if d.get("game"):
        parts.append("game_state=%s scene_id=%s requested=%s previous=%s scene_words=%s waiting_window=%s mission_ready=%s scene_task_step=%s"
                     % (d.get("game_state"), d.get("scene_id"), d.get("scene_requested"),
                        d.get("scene_previous"), _q(d.get("scene_words")), _hx(d.get("waiting_window")),
                        d.get("mission_ready"), d.get("scene_task_step")))
        parts.append("game=0x%08X hall_step=%s hall_flags=%s comeback=%s "
                     "+10615=%s +10611=%s +10613=%s +10619=%s task=%s "
                     "tuto=%s game4=%s wait=%s "
                     "scene=0x%08X(vt=%s) blockers=%s pump=0x%08X rows=%s"
                     % (d["game"], _hx(d.get("hall_step")), _hx(d.get("hall_flags")),
                        _hx(d.get("comeback_state")),
                        d.get("g10615"), d.get("g10611"), d.get("g10613"), d.get("g10619"),
                        _hx(d.get("hall_task")), _hx(d.get("tuto_step")),
                        _hx(d.get("game_plus4")), _hx(d.get("wait_state")),
                        d.get("scene") or 0, _hx(d.get("scene_vt")),
                        d.get("blockers"),
                        d.get("pump") or 0, d.get("mech_rows")))
        if d.get("pump"):
            parts.append("  pump +08=0x%X +0C=%s +10=0x%X"
                         % (d.get("pump_08") or 0, d.get("pump_0c"), d.get("pump_10") or 0))
    else:
        parts.append("game=NULL")
    return " | ".join(parts)


def change_key(d: dict):
    """只按阶段字段去重；消息对象里的计时器每帧都变，不能拿来触发高频日志。"""
    ignored = {"msgq"}
    return tuple(sorted((k, v) for k, v in d.items() if k not in ignored))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid-name", default="GundamOnline_CHINA.exe")
    ap.add_argument("--seconds", type=int, default=1800)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--file", default=os.path.join("server", "pilot_state.log"))
    args = ap.parse_args()

    if args.file:
        os.makedirs(os.path.dirname(os.path.abspath(args.file)), exist_ok=True)
    fh = open(args.file, "a", encoding="utf-8") if args.file else None

    def log(s):
        line = "%s %s" % (time.strftime("%H:%M:%S"), s)
        print(line, flush=True)
        if fh:
            fh.write(line + "\n")
            fh.flush()

    if fh:
        fh.write("\n===== probe start %s =====\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
        fh.flush()

    deadline = time.time() + args.seconds

    def wait_pid():
        t0 = time.time()
        while time.time() - t0 < 300 and time.time() < deadline:
            p = find_pid(args.pid_name)
            if p:
                return p
            time.sleep(0.5)
        return None

    log("[i] 等待进程 %s ...（会跟随 start_local 的 --retry 重启）" % args.pid_name)
    inst = 0
    while time.time() < deadline:
        pid = wait_pid()
        if not pid:
            log("[!] 没等到进程（或时间到）")
            return 2
        inst += 1
        log("[i] 第 %d 个实例 pid=%d" % (inst, pid))
        reader = None
        for _ in range(60):
            try:
                reader = Reader(pid)
                break
            except OSError:
                time.sleep(1)
        if reader is None:
            log("[!] OpenProcess 一直失败 —— 需要以管理员身份运行本脚本")
            return 3
        last = None
        while time.time() < deadline:
            p = find_pid(args.pid_name)
            if p != pid:
                log("[i] pid=%d 已退出，继续等下一个实例" % pid)
                break
            try:
                d = snapshot(reader)
            except OSError:
                log("[i] 读内存失败（进程可能已退出）")
                break
            key = change_key(d)
            if key != last:
                log(fmt(d))
                last = key
            time.sleep(args.interval)
        reader.close()
    if fh:
        fh.write("===== probe end =====\n")
        fh.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
