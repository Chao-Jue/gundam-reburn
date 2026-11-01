"""假认证服务器（30000）：分阶段脚本，用来逼出客户端的协议流程。

历史结论（见 server/网络层定位.md、.workbuddy/memory/2026-10-17.md）：
  · 客户端先发 16 字节握手块；
  · 服务端回 **32 字节**（内容无所谓，只要够 32 字节就会进 state 6）；
  · 之后客户端发 20 字节 = u32 LE 帧长(16) + 16 字节密文，
    明文恒为 `000ea934b90700005baa631300000000`（与账号无关）；
  · 再往后客户端等我们回包，等不到就 30 秒后断开（弹 A 2:0）。

本版新增 `--mode proto`：握手之后把客户端发来的那个 20 字节帧**原样回声**回去，
用零成本的方式试探"客户端是不是只要收到一帧就会继续"。

用法：
  python server/fake_auth.py                      # = --mode proto（推荐）
  python server/fake_auth.py --mode zeros32       # 只握手不回帧（对照组）
  python server/fake_auth.py --mode proto --echo-count 2

日志：server/fake_auth.log
"""
import argparse
import json
import os
import random
import select
import socket
import subprocess
import sys
import threading
import time
import struct

from hangar import (HangarStore, unit_add_body, EQUIPSET_WIRE_SIZE, MSSET_WIRE_SIZE,
                    MSSET_MAX_COUNT, encode_msset)
import hangar_experiment
import xwar_entry
import local_battle

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, 'fake_auth.log')
HANGAR_STORE = HangarStore(os.path.join(HERE, 'saved_hangar.json'))
HANGAR_EXPERIMENT = False
LOCAL_BATTLE = None
HANGAR_EXPERIMENT_STORE = HangarStore(os.path.join(HERE, 'saved_hangar.gm.json'))

DEFAULT_VARIANTS = ['zeros32', 'echo32', 'rand32', 'ff32', 'zeros16', 'zeros64']

_lock = threading.Lock()
_conn_idx = [0]

# 全局可变参数（main 里填）
KEYHEX = [None]      # 32 字节密钥材料 hex
INBOUND = [[]]       # 要伪造的"服务端→客户端"明文列表（hex 字符串）
SWEEP = []           # [(name, bytes)]：--sweep 模式下依次下发的候选
MISSING_BODY = ['wide']   # 缺表正文：wide（默认）/ comment / autoexec
REGION = ['CHINA']         # 占位行第 28 列的地区标签：CHINA / ALL / JAPAN
SET_TYPE = ['MAIN']        # 占位行第 4 列：MAIN / EX / SUB1 / NONE
SET_PART = ['NONE']        # 占位行第 5 列：NONE / L_HAND / R_HAND / ACTIVE_WEAPON

# 下行内层明文格式（0xbf0fc0 反汇编）：`u8 flag(0=明文) | u32 LE len | payload`
#
# 但 `len` 到底指什么还有两种解释没区分开：
#   A. len = payload 长度（不含 5 字节头）→ 第 19 轮试过 len=0x0b，客户端**立刻断开**
#   B. len = 整帧总长（含 5 字节头）     → 本轮要试 len=0x10（16 字节，正好一块）
# 单块上限 16 字节，所以 B 正好自洽：len=16 时 payload 恰好 11 字节。
# CGVOProtoAuth（0xBD1610）按首字节高 4 位分型。高 4 位 = 0 时：
#   byte0 = 0x00（宽度 0）
#   byte1 = payload 长度
#   随后是 payload；总长 = 2 + 长度
#   块内多出来的 00 会被当成下一条消息的头，最后剩 1 字节就永久卡住。
# 所以一条消息必须刚好占满 16 字节：00 0E | u16 操作码 | 12 字节 0。
# 操作码来自 0xA5B290 对 payload 首 u16 的比较。
AUTH_OPCODES = [0x1146, 0x298E, 0x4F3F, 0x60E0, 0x8F36, 0xA103, 0xA5DA, 0xDE24]

def auth_block(opcode):
    # 00 0E | opcode LE | 12 个 0  = 恰好 16 字节，一条完整消息
    return '000e' + opcode.to_bytes(2, 'little').hex() + '00' * 12

DEFAULT_SWEEP = [('op_%04x' % op, auth_block(op)) for op in AUTH_OPCODES]

# 默认不再盲发 8 条。顺序是：
#   1. 只发 0xDE24（3 个 u32，全 0）。首个 u32 >= 0 时 [proto+0x3CC]=1，
#      界面进入「登录中」，客户端发出 0xF24B。
#   2. 收到 0xF24B 后回 0xA5DA + 一个 >= 0 的 u32。
#      LoginAuth 的步骤从 1 变成 2，客户端接着会自己发 0x8288
#      （取战区列表），等待条变成「正在取得战区列表」。
#      u32 < 0 会把步骤写成 0x64，等于登录失败。
#   3. 收到 0x8288 后回 0x298E（一条战区）。0x43E700 用这条列表
#      离开等待条。记录最后一个 u32 是容量，不能为 0（那里有除法）。
LOGIN_TRIGGER = auth_block(0xDE24)


def login_ok_block(code=0):
    """一条 0xA5DA（正好 4 字节正文）再加一条 8 字节的未知操作码。

    密文块是 16 字节。0xA5DA 只占 8 字节，剩下的 8 字节必须也是一条
    完整消息，否则队尾会留下半个头，后面的轮询就卡住。
    """
    body = (0xA5DA).to_bytes(2, 'little') + (code & 0xFFFFFFFF).to_bytes(4, 'little')
    msg = bytes([0x00, len(body)]) + body
    pad = bytes([0x00, 0x06, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00])
    return (msg + pad).hex()


def _zstr(text, n, enc='utf-8'):
    raw = text.encode(enc, 'replace')
    if len(raw) >= n:
        raw = raw[:n - 1]
    return raw + b'\x00' * (n - len(raw))


def load_local_zone():
    """读 start_local.cmd 让 fake_http 下发的那份战区表。

    server/fake_root/launcher/authsv.csv，UTF-8。当前是：
    1,本地测试区,127.0.0.1,30000,1
    """
    path = os.path.join(HERE, 'fake_root', 'launcher', 'authsv.csv')
    zone = {'id': 1, 'name': '本地测试区', 'host': '127.0.0.1', 'port': 30000, 'image': 1}
    with open(path, 'r', encoding='utf-8-sig') as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 4:
                continue
            zone['id'] = int(parts[0] or zone['id'])
            zone['name'] = parts[1] or zone['name']
            zone['host'] = parts[2] or zone['host']
            zone['port'] = int(parts[3] or zone['port'])
            if len(parts) > 4 and parts[4]:
                zone['image'] = int(parts[4])
            break
    return zone


def worldlist_get_r(name=None, name_en='Test', host=None,
                    wid=None, selected=None, port=None, players=0, capacity=100, status=None):
    """0x298E，回答客户端的 send_worldlist_get（0x8288）。

    区号、名字、地址、端口、图片号默认取 load_local_zone()，和登录框同一份表。
    0x43E8E9 把名字交给 0xB110C0，代码页是 0xFDE9（UTF-8），不是 GBK。
    0xA5A380 按顺序读一条记录，线上 309 字节，写进 0x13C 的结构（中间有填充）。
    头三个 u32 是结果码、预选区号、条数。结果码必须 >= 0，条数 1..32。
    载荷 323 字节超过类型 0 宽度 0 的 255 上限，所以 byte0=0x01，后面跟 u16 长度。
    336 对齐后多出的 10 字节是一条完整的未知操作码，避免队尾留下半个头。
    """
    zone = load_local_zone()
    if name is None:
        name = zone['name']
    if host is None:
        host = zone['host']
    if wid is None:
        wid = zone['id']
    if selected is None:
        selected = wid
    if port is None:
        port = zone['port']
    if status is None:
        status = zone['image']
    if capacity == 0:
        capacity = 100
    rec = bytearray(309)
    rec[0:4] = (wid & 0xFFFFFFFF).to_bytes(4, 'little')
    rec[4:0x35] = _zstr(name, 0x31)
    rec[0x35:0x66] = _zstr(name_en, 0x31, 'ascii')
    rec[0x66:0x127] = _zstr(host, 0xC1, 'ascii')
    rec[0x127:0x12B] = (port & 0xFFFFFFFF).to_bytes(4, 'little')
    rec[0x12B:0x12D] = (status & 0xFFFF).to_bytes(2, 'little')
    rec[0x12D:0x131] = (players & 0xFFFFFFFF).to_bytes(4, 'little')
    rec[0x131:0x135] = (capacity & 0xFFFFFFFF).to_bytes(4, 'little')
    body = ((0).to_bytes(4, 'little')
            + (selected & 0xFFFFFFFF).to_bytes(4, 'little')
            + (1).to_bytes(4, 'little')
            + bytes(rec))
    payload = (0x298E).to_bytes(2, 'little') + body
    msg = bytes([0x01]) + len(payload).to_bytes(2, 'little') + payload
    pad = bytes([0x00, 0x08, 0xFF, 0xFF]) + b'\x00' * 6
    plain = msg + pad
    if len(plain) != 336:
        raise RuntimeError('worldlist plain %d' % len(plain))
    return plain.hex()


def lounge_ok_block(code=0, extra=0):
    """休息室 0xA5DA，回答 proto_lounge 的短 0xF24B（用户号 + otp）。

    正文是两个 u32。第一个 >= 0 时频道登录步骤加一，< 0 写成失败。
    和认证服那条 0xA5DA 不是同一条：那边只有一个 u32。
    """
    body = ((0xA5DA).to_bytes(2, 'little')
            + (code & 0xFFFFFFFF).to_bytes(4, 'little')
            + (extra & 0xFFFFFFFF).to_bytes(4, 'little'))
    msg = bytes([0x00, len(body)]) + body
    pad = bytes([0x00, 0x02, 0xFF, 0xFF])
    plain = msg + pad
    if len(plain) != 16:
        raise RuntimeError('lounge plain %d' % len(plain))
    return plain.hex()


def _align_message(msg):
    """补一条完整的未知操作码，使明文长度是 16 的倍数。"""
    gap = (-len(msg)) % 16
    if gap == 0:
        return msg
    if gap < 4:
        gap += 16
    plen = gap - 2
    return msg + bytes([0x00, plen]) + b'\xff\xff' + b'\x00' * (plen - 2)


def _kind0(payload, kind=None):
    """数据帧头：type=0，低 2 位 k = 长度字段宽度-1（k=0→1B, 1→2B, 2→3B, 3→4B）。

    kind=None 时按长度自动选；给 0/1/2/3 则强制。
    ⚠️ 2026-10-23 实测：客户端对 k=1 的 2 字节长度**只取了低 8 位**
    （发 0x0333=819，客户端认定 51），所以 >255 未必能用 k=1，需要用 --probe-kinds 试。
    """
    n = len(payload)
    if kind is None:
        if n <= 0xFF:
            kind = 0
        elif n <= 0xFFFF:
            kind = 1
        elif n <= 0xFFFFFF:
            kind = 2
        else:
            kind = 3
    if kind == 0:
        return bytes([0x00, n & 0xFF]) + payload
    if kind == 1:
        return bytes([0x01]) + (n & 0xFFFF).to_bytes(2, 'little') + payload
    if kind == 2:
        return bytes([0x02]) + (n & 0xFFFFFF).to_bytes(3, 'little') + payload
    return bytes([0x03]) + (n & 0xFFFFFFFF).to_bytes(4, 'little') + payload


def _settings_file(name):
    """download_list.csv 里的相对路径，文件在解密包的 settings 下。"""
    root = os.path.normpath(os.path.join(
        HERE, '..', 'GundamOnline_CHINA_已解密', 'decrypted', 'settings'))
    rel = name.replace('\\', '/').lstrip('/')
    path = os.path.normpath(os.path.join(root, rel.replace('/', os.sep)))
    if not path.startswith(root):
        return None
    if os.path.isfile(path):
        return path
    if rel == 'autoexec_sv.cfg':
        alt = os.path.join(root, 'autoexec.cfg')
        if os.path.isfile(alt):
            return alt
    return None


def parse_datafile_name(pt):
    """0xF86A：类型 0，文件名到第一个 0 为止，后面一个 u32。"""
    if len(pt) < 4 or (pt[0] >> 4) != 0:
        return None
    extra = pt[0] & 3
    if len(pt) < 2 + extra + 2:
        return None
    ln = int.from_bytes(pt[1:1 + 1 + extra], 'little')
    payload = pt[2 + extra:2 + extra + ln]
    if len(payload) < 4 or int.from_bytes(payload[:2], 'little') != 0xF86A:
        return None
    rest = payload[2:]
    z = rest.find(0)
    if z < 0:
        return None
    return rest[:z].decode('ascii', 'replace')


def parse_msg(pt):
    """通用入站消息解析：pt[0] 高位=长度编码种类，返回 (opcode, 正文)。
    与 parse_datafile_name 同一套索引约定，只是不假设具体操作码。"""
    if len(pt) < 2 or (pt[0] >> 4) != 0:
        return None, None
    extra = pt[0] & 3
    if len(pt) < 2 + extra + 2:
        return None, None
    ln = int.from_bytes(pt[1:1 + 1 + extra], 'little')
    payload = pt[2 + extra:2 + extra + ln]
    if len(payload) < 2:
        return None, None
    return int.from_bytes(payload[:2], 'little'), payload[2:]


def op_block(opcode, body, kind=None):
    """任意操作码的一条下行消息（16 字节对齐）。kind 可强制长度字段宽度。"""
    return _align_message(_kind0(opcode.to_bytes(2, 'little') + body,
                                kind=kind)).hex()


def body_70e9(rest, mode):
    """0x70E9 = 「CPS 模块校验报告」（`send_you9_cps_CLientCheck_response`）。

    rest 实测 = `05 00 00 00 | 00 00 00 00 | 00 00 00 00 | "<已被校验的模块>_<hash>"\\0`，
    路径实测出现过 `C:\\WINDOWS\\system32\\uxtheme.dll_a0ae2b2b`、
    `C:\\WINDOWS\\System32\\MSCTF.dll_36bd5c96`，
    也出现过 `Addr:4546C0, C:E93FC9B529, O:6AFF688825` 这种地址+代码指纹。

    它是**单向上报**（客户端自己的日志串就叫 `..._response`），不是请求-应答：
    镜像里查不到 `cmp eax,0x70E9`，93 条 lounge 接包 handler 和 282 条首级分发表里
    也都没有它 ⇒ 服务端回什么都没人读。5.0.0.33 上实测回了 114 次 `zero`，
    没有产生任何可观察影响（详见 server/0x70E9-应答实验.md §4）。

    none   —— 不回（默认：它不需要回执，少一个变量）
    zero   —— 3 个 0（历史上最常用的猜测，实测无害）
    ok4    —— 1 个 0
    mirror —— 把请求的前 12 字节原样回显
    echo   —— 整段正文回显
    """
    if mode == 'none':
        return None
    if mode == 'zero':
        return b'\x00' * 12
    if mode == 'ok4':
        return b'\x00' * 4
    if mode == 'mirror':
        return (rest + b'\x00' * 12)[:12]
    if mode == 'echo':
        return rest
    return b'\x00' * 12


PILOT_REC_LEN = 398   # 一条机师记录的线长；内存步长 0x1A8 = 424
PILOT_BODY_LEN = 4 + PILOT_REC_LEN * 2 + 12 + 4 + 1   # = 817（bmgpack 为空）


def pilot_entry(pid=5, name='TEST', troops=0, level=1, mil_class=0,
                raw_len=PILOT_REC_LEN):
    """一条 398 字节的机师记录（线格式，见 server/0xE13A-驾驶员列表格式.md §3）。

    离线核验：FUN_00a956f0 的读取序列逐项相加 = 398，各字段线偏移与
    refs/msgo-doc/.../07-机师列表创建选择.md §3.3 的 58 字段表逐行吻合。
    """
    b = bytearray(raw_len)
    b[0:4] = (pid & 0xFFFFFFFF).to_bytes(4, 'little')           # +0   pilot_id
    nm = name.encode('utf-8', 'replace')[:24]
    b[4:4 + len(nm)] = nm                                       # +4   name[25] 定长无 NUL
    # +29 last_in u32 / +33 troops u8 / +34 level u8 / +35 mil_class u8
    b[33] = troops & 0xFF                                       # troops：**1=联邦 / 2=吉翁**（0 不是合法值）
    b[34] = level & 0xFF
    b[35] = mil_class & 0xFF
    # +36 byword u16 / +38 avatar[18] / +56 cmdr_fame ... 其余留 0
    return bytes(b)


def pilot_list_body(n_eff=1, n_zeon=1, name='TEST', entry_len=PILOT_REC_LEN):
    """0xE13A 正文（本客户端 v5.0.0.33 的真实布局，全部零填 = 817 字节）：

        u32  result
        398  pilots_eff     ← 固定 1 条，**没有 count 前缀**
        398  pilots_zeon    ← 固定 1 条，没有 count 前缀
        u32  del_remain_sec_eff
        u32  del_remain_sec_zeon
        u32  charge_point
        u32  bmgpack_count (<=0x10)
        23n  bmgpack_list
        u8   is_tutorial_end      ← 读完必须「游标 == 正文末尾」

    证据：0xACFE1F.. 分支 `vt[0x78](0x4E5)` 分配 1253 =
        4 + 424 + 424 + 4*3 + 4 + 0x10*24 + 1（逐项精确相等）；
        两处 `cmp edi,1; jb` 证明每侧硬编码只读 1 条；
        0xAD007D `cmp cur,[end]; je` 是唯一的成功判据。

    n_eff / n_zeon 只当开关用（0 = 该侧留 398 个零字节），不改变长度。
    """
    out = bytearray()
    out += (0).to_bytes(4, 'little')                            # result
    out += pilot_entry(5, name, 0) if n_eff else bytes(entry_len)      # pilots_eff
    out += pilot_entry(6, name, 1) if n_zeon else bytes(entry_len)     # pilots_zeon
    out += (0xFFFFFFFF).to_bytes(4, 'little')                  # del_remain_sec_eff（-1＝未进入删除）
    out += (0xFFFFFFFF).to_bytes(4, 'little')                  # del_remain_sec_zeon
    out += (0).to_bytes(4, 'little')                            # charge_point
    out += (0).to_bytes(4, 'little')                            # bmgpack_count
    out += bytes(1)                                             # is_tutorial_end
    return bytes(out)


def pilot_body(result=0, eff=None, zeon=None, bmg=0, tut=0,
               entry_len=PILOT_REC_LEN):
    """按 §1 布局拼一条 0xE13A 正文，各字段可控（用于变体实验）。

    eff / zeon 传 None 表示该侧留 entry_len 个零字节（= 没有机师）。
    bmg > 0 时追加 23*bmg 字节，总长 = 817 + 23*bmg。
    """
    out = bytearray()
    out += (result & 0xFFFFFFFF).to_bytes(4, 'little')
    out += eff if eff else bytes(entry_len)
    out += zeon if zeon else bytes(entry_len)
    out += (0xFFFFFFFF).to_bytes(4, 'little')              # del_remain_sec_eff（-1＝未进入删除）
    out += (0xFFFFFFFF).to_bytes(4, 'little')              # del_remain_sec_zeon
    out += (0).to_bytes(4, 'little')                        # charge_point
    out += (bmg & 0xFF).to_bytes(4, 'little')               # bmgpack_count
    out += bytes(23 * bmg)                                  # bmgpack_list
    out += bytes([tut & 0xFF])                              # is_tutorial_end
    return bytes(out)


# 变体表：名字 -> 正文构造器。顺序由 --pilot-variants 决定，这里只定义。
PILOT_VARIANTS = {
    'zero':   lambda: pilot_body(0, None, None, 0, 0),
    'res1':   lambda: pilot_body(1, pilot_entry(5, 'TEST', 0),
                                 pilot_entry(6, 'ZEON', 1), 0, 0),
    'resm1':  lambda: pilot_body(-1, pilot_entry(5, 'TEST', 0),
                                 pilot_entry(6, 'ZEON', 1), 0, 0),
    'eff':    lambda: pilot_body(0, pilot_entry(5, 'TEST', 0), None, 0, 0),
    'both':   lambda: pilot_body(0, pilot_entry(5, 'TEST', 0),
                                 pilot_entry(6, 'ZEON', 1), 0, 0),
    'tut':    lambda: pilot_body(0, pilot_entry(5, 'TEST', 0),
                                 pilot_entry(6, 'ZEON', 1), 0, 1),
    'bmg1':   lambda: pilot_body(0, pilot_entry(5, 'TEST', 0),
                                 pilot_entry(6, 'ZEON', 1), 1, 0),
    # --- 18:56 加：把"有效记录"拆成单字段，定位到底哪个字段触发客户端断连 ---
    'id5':    lambda: pilot_body(0, pilot_entry(5, '', 0), None, 0, 0),
    'id5z6':  lambda: pilot_body(0, pilot_entry(5, '', 0),
                                 pilot_entry(6, '', 1), 0, 0),
    'nm':     lambda: pilot_body(0, pilot_entry(0, 'TEST', 0), None, 0, 0),
    'lvl':    lambda: pilot_body(0, pilot_entry(0, '', 0, level=1), None, 0, 0),
    # --- 19:00 加：id 与名字必须同时存在才会触发，继续拆"哪一侧/哪些字段" ---
    'zeononly': lambda: pilot_body(0, None, pilot_entry(6, 'ZEON', 1), 0, 0),
    'notroop':  lambda: pilot_body(0, pilot_entry(5, 'TEST', 0),
                                   pilot_entry(6, 'ZEON', 0), 0, 0),
    # --- 19:35 加：按参考文档 §3.3，troops 是 1=联邦 / 2=吉翁（之前填 0/1 是错的）---
    'both_t12': lambda: pilot_body(0, pilot_entry(5, 'TEST', 1),
                                   pilot_entry(6, 'ZEON', 2), 0, 0),
    'eff_t1':   lambda: pilot_body(0, pilot_entry(5, 'TEST', 1), None, 0, 0),
    'zeon_t2':  lambda: pilot_body(0, None, pilot_entry(6, 'ZEON', 2), 0, 0),
    # --- 19:55 加：外观用真表（pilot_form.csv）的合法值 ---
    # 注意 troops 线上是 0 基：0=秩序/eff、1=抵抗/zeon（参考文档 §3.11 规则③）
    'real_eff':  lambda: pilot_body(0, pilot_entry_real(1, 'TEST', 0), None, 0, 0),
    'real_both': lambda: pilot_body(0, pilot_entry_real(1, 'EFF01', 0),
                                    pilot_entry_real(2, 'ZEO01', 1, avatar_id=2), 0, 0),

    # eff/zeon 两条都按'当前世界(秩序/troops=0)'填，只改 pid/名字：
    # 用来判断 real_both 被踢回登录是不是因为 zeon 那条写了 troops=1。
    'real_same_world': lambda: pilot_body(0, pilot_entry_real(1, 'EFF01', 0),
                                            pilot_entry_real(2, 'EFF02', 0), 0, 0),

    # 固定槽不能真的省略，也不能把未使用槽的 avatar 全清零。pilot_id=0 表示空槽，
    # 其余会被 UI 回调读取的字段仍填该阵营的合法默认值（ZEON 男性默认 avatar_id=17）。
    'vacant_both': lambda: pilot_body(0, pilot_entry_vacant(0, avatar_id=1),
                                      pilot_entry_vacant(1, avatar_id=17), 0, 0),
    'real_eff_vacant': lambda: pilot_body(0, pilot_entry_real(1, 'EFF01', 0),
                                          pilot_entry_vacant(1, avatar_id=17), 0, 0),
}


# ---------------------------------------------------------------------------
# 合法 avatar 子结构（18B 线格式）—— 取值全部来自真表
#   GundamOnline_CHINA_已解密/decrypted/settings/pilot_form.csv
#   线布局（= FUN_00a5de30 的读取顺序）：
#     +0 u32 avatar_id | +4 u8 gender | +5 u8 face | +6 u8 skincolor
#     +7 u16 clothes | +9 u32 hair | +13 u8 accessory | +14 u8 frame
#     +15 u8 voice | +16 u16 ?
#   pilot_form.csv 的行：avatar_id,種別,軍タイプ,性別タイプ,バリエーション,パーツID,名前
#   avatar_id=1（联邦男性1）的默认：SKIN=01 CLOTHES=00801 HAIR=01005 VOICE=1 FRAME=0
# ---------------------------------------------------------------------------
AVATAR_FORM_CSV = os.path.normpath(os.path.join(
    HERE, '..', 'GundamOnline_CHINA_已解密', 'decrypted', 'settings', 'pilot_form.csv'))


def _load_pilot_form():
    """读 pilot_form.csv → {avatar_id: {種別: [ (軍,性別,variation,parts_id,名), ... ]}}"""
    out = {}
    try:
        txt = open(AVATAR_FORM_CSV, 'rb').read().decode('utf-8', 'replace')
    except Exception:  # noqa: BLE001
        return out
    for line in txt.splitlines():
        if not line or line.startswith('#'):
            continue
        c = line.split(',')
        if len(c) < 7 or not c[0].strip().isdigit():
            continue
        aid = int(c[0])
        out.setdefault(aid, {}).setdefault(c[1], []).append(
            (c[2].strip(), c[3].strip(), c[4].strip(), c[5].strip(), c[6].strip()))
    return out


_PILOT_FORM = None


def pilot_form():
    global _PILOT_FORM
    if _PILOT_FORM is None:
        _PILOT_FORM = _load_pilot_form()
    return _PILOT_FORM


def avatar_wire(avatar_id=1, gender=0, face=None, skin=None, clothes=None,
                hair=None, accessory=0, frame=None, voice=None):
    """按真表生成 18 字节 avatar 线块；不传的字段取该 avatar_id 的 DEF_* 默认值。"""
    kinds = pilot_form().get(avatar_id, {})

    def pick(kind, def_kind=None, idx=0):
        arr = kinds.get(kind) or (kinds.get(def_kind) if def_kind else None) or []
        if not arr:
            return 0
        return int(arr[min(idx, len(arr) - 1)][2] or 0)

    face = pick('FACE', idx=0) if face is None else face
    skin = pick('DEF_SKIN') if skin is None else skin
    clothes = pick('DEF_CLOTHES') if clothes is None else clothes
    hair = pick('DEF_HAIR') if hair is None else hair
    frame = pick('DEF_FRAME', 'FRAME') if frame is None else frame
    voice = pick('DEF_VOICE') if voice is None else voice

    b = bytearray(18)
    b[0:4] = (avatar_id & 0xFFFFFFFF).to_bytes(4, 'little')
    b[4] = gender & 0xFF
    b[5] = face & 0xFF
    b[6] = skin & 0xFF
    b[7:9] = (clothes & 0xFFFF).to_bytes(2, 'little')
    b[9:13] = (hair & 0xFFFFFFFF).to_bytes(4, 'little')
    b[13] = accessory & 0xFF
    b[14] = frame & 0xFF
    b[15] = voice & 0xFF
    b[16:18] = b'\x00\x00'
    return bytes(b)


def pilot_entry_real(pid=1, name='TEST', troops=0, level=1, avatar_id=1, gender=0,
                     avatar=None):
    """一条"取值全合法"的 398B 记录：外观来自 pilot_form.csv 的真值。"""
    b = bytearray(pilot_entry(pid, name, troops, level=level))
    b[38:56] = avatar if avatar is not None else avatar_wire(avatar_id, gender)
    return bytes(b)


CREATE_REC_LEN = 157
CREATE_REQ_LEN = CREATE_REC_LEN + 4
PILOT_STORE = os.path.join(HERE, 'saved_pilots.json')


def account_from_login(rest):
    """0xF24B 的第一个字符串是账号。休息室短包没有账号，返回空串。"""
    if len(rest) < 20:
        return ''
    parts = [s for s in _cstrs(rest) if s]
    if not parts:
        return ''
    name = parts[0].decode('utf-8', 'replace')
    if name.isprintable() and 1 <= len(name) <= 32:
        return name
    return ''


def _load_pilot_store():
    try:
        with open(PILOT_STORE, encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_pilot_store(data):
    tmp = PILOT_STORE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, PILOT_STORE)


def save_created_pilot(account, record, slot):
    """保存一条创建记录。pilot_id 为 0 时分配新 ID，并按阵营+槽位覆盖。"""
    if len(record) != CREATE_REC_LEN:
        raise ValueError('创建记录长度 %d' % len(record))
    account = account or 'default'
    data = _load_pilot_store()
    acc = data.setdefault(account, {'next_id': 1, 'slots': {}})
    rec = bytearray(record)
    pid = int.from_bytes(rec[:4], 'little')
    nxt = int(acc.get('next_id') or 1)
    if pid == 0:
        pid = max(1, nxt)
        rec[:4] = pid.to_bytes(4, 'little')
        nxt = pid + 1
    acc['next_id'] = max(nxt, pid + 1)
    troops = rec[29]
    acc.setdefault('slots', {})['%d:%d' % (troops, slot)] = rec.hex()
    data[account] = acc
    _save_pilot_store(data)
    return bytes(rec)


def saved_pilot_records(account):
    """返回 {0: eff记录或None, 1: zeon记录或None}。"""
    acc = _load_pilot_store().get(account or 'default') or {}
    out = {0: None, 1: None}
    for key, hx in (acc.get('slots') or {}).items():
        try:
            troops = int(str(key).split(':', 1)[0])
            rec = bytes.fromhex(hx)
        except ValueError:
            continue
        if troops in out and len(rec) == CREATE_REC_LEN:
            out[troops] = rec
    return out


def list_entry_from_create(record):
    """把 157B 创建记录转换成 398B 列表记录。

    两个读取器的公共身份字段并不等长：列表在名字后多一个 u32 last_in，
    创建记录则在外观前多一组战绩字段。外观都是紧凑的 18 字节。
    """
    b = bytearray(PILOT_REC_LEN)
    b[0:4] = record[0:4]
    b[4:29] = record[4:29]
    b[33] = record[29]                 # troops
    b[34] = record[30]                 # level
    b[35] = record[31]                 # mil_class
    b[36:38] = record[32:34]           # byword
    b[38:56] = record[46:64]           # avatar
    b[56:60] = record[34:38]           # cmdr_fame
    return bytes(b)


AUTH_ACCOUNT = {'name': ''}
LOUNGE_OTP = 'local'
LOUNGE_SESSIONS = {}


def remember_auth_account(name):
    if name:
        AUTH_ACCOUNT['name'] = name


def bind_lounge_session(user_id, otp, account):
    """选区应答里的用户号 + otp 是休息室连接认人的凭据。"""
    if account:
        LOUNGE_SESSIONS[(int(user_id), otp)] = account


def lounge_identity(rest):
    """休息室 0xF24B：u32 用户号 + NUL 结尾 otp。"""
    if len(rest) < 5:
        return None
    user_id = int.from_bytes(rest[:4], 'little')
    otp = rest[4:].split(b'\x00', 1)[0].decode('ascii', 'replace')
    return user_id, otp


def adopt_unbound_pilots(account):
    """把尚未绑到账号上的新建机师并入该账号的同槽位。"""
    if not account or account == 'default':
        return
    data = _load_pilot_store()
    src = ((data.get('default') or {}).get('slots') or {})
    if not src:
        return
    acc = data.setdefault(account, {'next_id': 1, 'slots': {}})
    slots = acc.setdefault('slots', {})
    slots.update(src)
    acc['next_id'] = max(int(acc.get('next_id') or 1),
                         int((data.get('default') or {}).get('next_id') or 1))
    data.pop('default', None)
    _save_pilot_store(data)


def pilot_select_body():
    """0x063E 定长正文。当前客户端的 pilot_detail 为 29514 字节。

    旧参考版的 51672 字节详情在这个版本已经缩短，多发或少发都会让游标对不上结尾。
    """
    detail = bytearray()
    # 占位：后续替换真实机师详情。解析器 0xA95230 的前 4 字节是 exp，
    # 不是 pilot_id。经验保持为 0 时角色等级也是 0。
    detail += (100).to_bytes(4, 'little')
    detail += bytes(60)          # money、战绩和其余固定前缀
    if HANGAR_EXPERIMENT:
        # A95230 prefix: six u32 then deckcost u16 -> memory+18(hex).
        # Experiment capacity only; preserve ordinary pilot initialization.
        struct.pack_into('<H', detail, 24, hangar_experiment.DECK_COST_CAPACITY)
    detail += bytes(115)         # comment
    detail += bytes(128)         # hav_medal，16×8
    detail += bytes(64)          # hav_emblem，8×8
    detail += bytes(768)         # hav_avatar，96×8
    detail += bytes(64)          # hav_voice，8×8
    detail += bytes(512)         # hav_modules，128×u32
    detail += bytes(68)          # examination
    detail += bytes(16)          # 两段 8 字节
    detail += bytes(8)           # 两个 u32
    detail += bytes(192)         # cshist，32×6
    detail += bytes(1 + 4)       # u8 + u32
    detail += bytes(1024)        # hav_rental_module，128×8
    detail += bytes(4)           # dc_point
    detail += bytes(400 * 66)    # favms_arr，每条末尾还有 1 字节
    detail += bytes(40)          # heroms_grants
    detail += bytes(8 + 16)      # uniqid、周期奖励和四个 u32
    detail += bytes(2 + 4 + 2 + 4 + 2 + 2)  # 末尾定长字段
    detail += bytes(2)                       # 成功路径在 0x7CFC 还会再读一个 u16
    if len(detail) != 29514:
        raise RuntimeError('pilot_detail %d' % len(detail))
    body = bytearray()
    body += bytes(28)            # result、restore、charge、tuto_step、tuto_flags、mission
    # 占位：后续替换该机师的真实教程进度。
    # 客户端枚举：0=UNKNOWN，1=END，100 起才是各段新手教程，9999=FINAL。
    # 0 会进入新手教程加载，当前没有教程战场可进，所以停在白屏。
    body[12:16] = (1).to_bytes(4, 'little')
    body += detail
    # is_processing_comeback 必须是 0。
    # 非 0 会把 game+0x105A0 写成 1；加载界面只在该值为 0 且步骤到 0x14 时往下走。
    # 旧文档里“非 0 才开大厅”是另一条回归活动路径，这条客户端走不到。
    tail = bytearray(19)         # netcafe、comeback=0、vip、overplay、三组计数
    body += tail
    body += b'\x00'             # heroms_term 空串
    body += bytes(1)            # flag_wideuse = 0
    body += bytes(4)            # level_point
    if len(body) != 29567:
        raise RuntimeError('select body %d' % len(body))
    return bytes(body)


def channel_entry(channel_id=1, name='本地频道'):
    """一条频道记录。解析器 0xA94CE0 正好读 54 字节。

    偏移 41 的 type 会被当成大厅场景编号。当前客户端 0x433A80 的映射是：
    4→目的地 1，6→3，8→2，17→4，19→5；13 不发送；其余（含 0）目的地为 0。
    目的地 0 不会建立大厅场景，加载窗口后面就是白屏。
    4 是映射表里的第一个有效大厅场景。这是占位，之后按真实频道类型替换。
    """
    raw = name.encode('utf-8', 'replace')[:37]
    entry = bytearray(54)
    entry[0:4] = (channel_id & 0xFFFFFFFF).to_bytes(4, 'little')
    entry[4:4 + len(raw)] = raw
    entry[41] = 4                               # 占位场景编号，后续替换真实频道类型
    entry[42] = 1                               # pilot level min
    entry[43] = 99                              # pilot level max
    entry[48:50] = (100).to_bytes(2, 'little')  # user_max
    if len(entry) != 54:
        raise RuntimeError('channel entry %d' % len(entry))
    return bytes(entry)


def channel_list_body():
    entry = channel_entry()
    return (1).to_bytes(4, 'little') + entry


def iter_type0(pt):
    """拆开一个明文流里连续的 type0 消息。"""
    out = []
    i = 0
    while i + 2 <= len(pt):
        if (pt[i] >> 4) != 0:
            break
        extra = pt[i] & 3
        hdr = 2 + extra
        if i + hdr > len(pt):
            break
        ln = int.from_bytes(pt[i + 1:i + hdr], 'little')
        if ln < 2 or i + hdr + ln > len(pt):
            break
        payload = pt[i + hdr:i + hdr + ln]
        out.append((int.from_bytes(payload[:2], 'little'), payload[2:]))
        i += hdr + ln
    return out


# 大厅初始化占位。客户端按固定顺序要这些数据，缺一条就停在白屏。
# 下面的正文只保证“长度合法、count=0、游标到底”，数值全是空的。
# 以后填真实数据时改对应的构造函数，不要改应答操作码和总长度公式。
HALL_OPS = {
    0xFC4B,  # reservation status polling
    0x846A,  # enter an assigned cross-world battle room
    0x2EFF,  # local experimental reservation
    0xBEDC,  # cancel local reservation
    0x0AA5,  # 武器槽变更；按已持有资产验证并持久化
    0x9527,  # 装备记忆（装备组保存）；正文 = uniqid u64 + 121B 装备组块
    0x9A9D,  # 机体组列表请求（空正文）；不回的话「机体组」面板永远是空的
    0xA76E,  # 机体组保存（把机体加进「机体设置NN」）；正文 = 95B 机体组块
    0x550A,  # 武器开发/解锁；正文 20B = uniqid u64 + item_id u32 + use_gp u32 + use_bc u32
    0xA28F,  # 武器开发 complete（三段式的第三段）；「开发」按钮不会走到，先纳入白名单免得整帧被丢
    0x34AB,  # 武器开发 estimate（三段式的第二段）；同上
    0xC475,  # 场景目的地通知；无直接应答，但触发任务信息主动推送
    0x48F2,  # 战绩
    0xE9A2,  # 常用机体
    0x2F63,  # 机师卡片
    0x3C26,  # 道具回购删除期限
    0x1B98,  # 跨世界战预约选项
    0x0680,  # 大厅活动消息
    0xD9AE,  # 机师排行榜
    0xD377,  # 频道大厅成员
    0x7CCB,  # CP 价格
    0x05A5,  # 排行初始化
    0x947E,  # 道具初始化
    0x16AC,  # 机体初始化（要回两条）
    0x9A9D,  # 机体套装
    0xDCA1,  # 任务单位
    0xB681,  # 活动标志
    0x921B,  # 屏蔽列表
}

# 这些请求在协议上本来就没有逐请求应答，不能因为它们和有应答请求
# 合并在一个明文帧里，就把整帧丢掉。
HALL_NO_REPLY_OPS = {
    0x1C33,  # save_message
}


def _req_u32(rest, off, default=1):
    if len(rest) < off + 4:
        return default
    return int.from_bytes(rest[off:off + 4], 'little')


def hall_reply(op, rest, account):
    """返回 (应答操作码, 正文)。正文目前是占位。"""
    pilot_id = _req_u32(rest, 0)
    world_id = _req_u32(rest, 4)

    if op == 0xE9A2:
        # 0x3620：result u32 | pilot_id u32 | world_id u32 | count u32
        # count=0 时没有 66B 常用机体元素。以后在 count 后面追加元素。
        body = (b'\x00\x00\x00\x00'
                + pilot_id.to_bytes(4, 'little')
                + world_id.to_bytes(4, 'little')
                + b'\x00\x00\x00\x00')
        return 0x3620, body
    if op == 0x2F63:
        # 0xB4B6：result u32 | world_id u32 | 398B 机师卡片。
        # 卡片目前复用存档里的列表记录，战绩和部队字段仍是 0。
        slots = saved_pilot_records(account)
        card = (list_entry_from_create(slots[0]) if slots.get(0)
                else pilot_entry_vacant(0, avatar_id=1))
        body = b'\x00\x00\x00\x00' + world_id.to_bytes(4, 'little') + card
        return 0xB4B6, body
    if op == 0x3C26:
        # 0x994C：道具回购删除期限字符串（NUL 结尾、上限 65B）。
        # 占位：空字符串；以后替换为服务器实际期限文本。
        return 0x994C, b'\x00'
    if op == 0x1B98:
        # 0xCCDF：跨世界战预约选项，固定 554B。
        # 结构是 5×u32 + 10×u16 + (u16 + 128×u32)。
        # 占位：所有选项为 0；以后替换为真实赛季和预约配置。
        return 0xCCDF, bytes(554)
    if op == 0x0680:
        # 0x5A3D：u32 count + count×356B 活动消息。
        # 占位：没有活动消息；以后从活动/公告数据生成。
        return 0x5A3D, bytes(4)
    if op == 0xD9AE:
        # 0xB985：机师排行榜。
        # result/is_revoke(8B) | order(10B) | rankself(40B)
        # | page_now/page_max(8B) | ranking_count/top_count(8B)
        # | term_str(NUL)。两个 count 都为 0 时正文固定 75B。
        # 占位：空榜；以后填真实名次、本人排名、榜期和列表。
        return 0xB985, bytes(74) + b'\x00'
    if op == 0xD377:
        # 0x1D02 没有 result：回显 is_simple | world_client_num | count。
        # 当前客户端的成员记录与创建记录共用 157B 线格式（旧参考版为
        # 159B）。大厅至少要包含当前机师，否则成员回调虽然成功，场景里
        # 却没有本机对象可建立。以后联机时再追加其他在线机师。
        is_simple = _req_u32(rest, 0, 0)
        slots = saved_pilot_records(account)
        member = next((rec for rec in slots.values() if rec), None)
        if member:
            return 0x1D02, (is_simple.to_bytes(4, 'little')
                            + (1).to_bytes(4, 'little')   # world_client_num
                            + (1).to_bytes(4, 'little')   # count
                            + member)
        # 没有存档时的占位空列表；以后应由在线会话数据生成。
        return 0x1D02, is_simple.to_bytes(4, 'little') + bytes(8)
    if op == 0x7CCB:
        # 0x9397：9 个 u32，共 36B。无 result。
        # 顺序：机体仓库、道具仓库、部队徽章、部队 NPC、机体能量、
        # 卡组费用、外观重置、reserve3、reserve4。
        return 0x9397, bytes(36)
    if op == 0x05A5:
        # 0x7C8A：is_revoked u32 | high_count u32 | event_count u32。
        # 两个 count 都是 0，所以没有 u16 分数。12B。
        return 0x7C8A, bytes(12)
    if op == 0x48F2:
        # 0xDC47：1857B 空战绩。
        # result u32 | pilot_id u32 | world_id u32
        # | precord 242B | badge 3×152B | medal 16×8B
        # | deck 2×324B | 历史 369B | lvjudge u16
        body = bytearray(1857)
        body[4:8] = pilot_id.to_bytes(4, 'little')
        body[8:12] = world_id.to_bytes(4, 'little')
        return 0xDC47, bytes(body)
    if op == 0x947E:
        # 0x02EE：空仓库 64B。四类物品 count 都是 0，没有 22B 物品元素。
        # slot u16×4 | 排序时间 u32×6 | count u32×4 | 方案排序 u32×4
        return 0x02EE, bytes(64)
    if op == 0x9A9D:
        # 0x356F：count u32 = 0。以后每套机体追加一条记录。
        return 0x356F, bytes(4)
    if op == 0xDCA1:
        # 0x36D9：count u32 = 0。
        return 0x36D9, bytes(4)
    if op == 0xB681:
        # 0xE0DE：活动标志 u64 = 0。
        return 0xE0DE, bytes(8)
    if op == 0x921B:
        # 0xCE1A：result u32 | id_count u32 | wid_count u32。两个列表都空。
        return 0xCE1A, bytes(12)
    return None


def hall_replies(op, rest, account, pilot_id=1):
    """个别请求要连续回两条。返回 [(opcode, body), ...]。"""
    if HANGAR_EXPERIMENT and op == 0x2EFF:
        record = next((rec for rec in saved_pilot_records(account).values()
                       if rec is not None and int.from_bytes(rec[:4], 'little') == pilot_id), None)
        troops = record[29] if record else None
        response = xwar_entry.BOOKINGS.register(account, pilot_id, rest, troops=troops)
        if LOCAL_BATTLE is not None and record is not None and response[:4] == bytes(4):
            room = LOCAL_BATTLE.reserve(account, pilot_id, record)
            log('  [xwar] local preparation room %s' % ('allocated' if room else 'unavailable'))
        return [(0xD52A, response)]
    if HANGAR_EXPERIMENT and op == 0xFC4B:
        return xwar_entry.BOOKINGS.info_replies(account, pilot_id, rest)
    if HANGAR_EXPERIMENT and op == 0x846A:
        response = xwar_entry.BOOKINGS.enter(account, pilot_id, rest)
        return [(0x5383, response)] if response is not None else []
    if HANGAR_EXPERIMENT and op == 0xBEDC:
        response = xwar_entry.BOOKINGS.cancel(account, pilot_id, rest)
        return [(0x736E, response)] if response is not None else []
    if op == 0xC475:
        # 主动推送，不是 C475 的逐请求应答。当前 exe 的主菜单任务
        # 0x9EA89D 等待 game+0x312B0；DBBC 回调 0x43F170 会置 1。
        # 解析器 0xACD84E: 三组 4×u64 + u8，无 result/count 字段。
        # 占位：空协作任务位图。以后替换为该机师真实任务状态。
        pushes = [(0xDBBC, bytes(3 * 4 * 8 + 1))]
        if HANGAR_EXPERIMENT:
            pushes.append((0xB080, xwar_entry.mission_info_body()))
        return pushes
    if op == 0x16AC:
        # 0x2ACF 是 28B 定长（客户端 recv_msma_init_get_r_begin，处理器 0xAAA848，
        # `push 0x1c` 预留正好 28）：
        # sv_time u32 | slot_num u16 | sort_sec u32 | sort_usec u32
        # | penalty u16 | bonus u16 | balance u16 | sort_type u32 | sort_order u32
        # ↑ slot_num = 紧随其后的 0xA832 记录条数（不是仓库容量）。客户端自己的
        #   日志串就叫它 slot_num，且是 recv_msma_init_get_r_begin 的字段；
        #   0xAAA848 把它连同另外 8 个字段一起交给 vt[0x21c]。按"条数"理解是唯一
        #   在 9.0.0.235 上通过单变量实验的读法，5.0.0.33 对偏大值也只是不敏感。
        # 0xFCE6 必须是空正文，多一个字节客户端会丢掉整条。
        units = HANGAR_STORE.units(account, pilot_id)
        if HANGAR_EXPERIMENT:
            with HANGAR_EXPERIMENT_STORE.lock:
                units = HANGAR_EXPERIMENT_STORE.units(account, pilot_id)
                if not units:
                    units = [hangar_experiment.gm_unit()]
                    HANGAR_EXPERIMENT_STORE.replace_units(account, pilot_id, units)
                else:
                    upgraded = [hangar_experiment.upgrade_unarmed_unit(unit) for unit in units]
                    if upgraded != units:
                        HANGAR_EXPERIMENT_STORE.replace_units(account, pilot_id, upgraded)
                        units = upgraded
        begin = bytearray(28)
        # 0x604830 accepts sort types 1..13 only. Type 0 makes 0x5E0600
        # leave the sorted vector empty; 0x787BB6 then dereferences null.
        struct.pack_into('<II', begin, 20, 1, 0)
        # slot_num 就是本次下发的 0xA832 条数；空仓库自然是 0。
        struct.pack_into('<H', begin, 4, min(len(units), 0xFFFF))
        return ([(0x2ACF, bytes(begin))]
                + [(0xA832, unit_add_body(unit)) for unit in units]
                + [(0xFCE6, b'')])
    if op == 0x0AA5:
        try:
            store = HANGAR_EXPERIMENT_STORE if HANGAR_EXPERIMENT else HANGAR_STORE
            return [(0xD9DB, store.change_weapon(account, pilot_id, rest))]
        except ValueError as error:
            log('  [hangar] 武器变更被拒绝: %s' % error)
            # Well-formed failure response preserves the requested identity.
            if len(rest) != 14:
                return []
            return [(0xD9DB, struct.pack('<i', -1) + rest)]
    if op == 0x550A:
        # 0x550A msma_weapon_unlock：格纳库武器列表的「开发」按钮。
        # 发送端 0xAE4100（日志串 send_msma_weapon_unlock）定长 0x16=22B：
        #   写 0x550A 于 +0；正文 = uniqid u64 | item_id u32 | use_gp u32 | use_bc u32 = 20B。
        # 实测报文：01 1a cf e8 b4 00 00 00 | 92 db 0b 00 | 00 00 00 00 | 00 00 00 00
        #   → uniqid=777000000001、item_id=777106、use_gp=use_bc=0。
        # 回复 0x45E4 msma_weapon_unlock_r：handler 在 0xAAE0B5（0xAAE0AA 处
        # `cmp eax,0x45E4 / jne` 顺序落下，没有跳转指令指向它）。
        # 正文必须恰好 17B，见 unlock_reply_body 的推导。
        if len(rest) < 12:
            log('  [hangar] 0x550A 正文只有 %d 字节，忽略' % len(rest))
            return []
        uniqid, item_id = struct.unpack_from('<QI', rest, 0)
        store = HANGAR_EXPERIMENT_STORE if HANGAR_EXPERIMENT else HANGAR_STORE
        index = {w['item_id']: i for i, w in enumerate(hangar_experiment.all_definitions())}
        db_index = index.get(item_id, 0)
        try:
            added = hangar_experiment.unlock_weapon(store, account, pilot_id, uniqid, item_id)
        except ValueError as error:
            log('  [hangar] 武器解锁被拒绝: %s' % error)
            return [(0x45E4, unlock_reply_body(uniqid, item_id, db_index, result=-1))]
        log('  [hangar] 武器解锁 %s item=%d uniqid=%d db_index=%d'
            % ('新增' if added else '已持有', item_id, uniqid, db_index))
        return [(0x45E4, unlock_reply_body(uniqid, item_id, db_index))]
    if op == 0x9527:
        # 0x9527 msma_equipset_store：装备界面的「装备记忆」按钮。
        # 发送端 0xAE5480（日志串 0xE13120），`push 0x86` 预留 134B，
        #   正文 = uniqid u64 | 121B 装备组块（序列化器 0xA948C0）。
        # 实测 129B：uniqid + a u32 | b u32 | slot u16 | weapons 3u32 |
        #            shield u32 | d u32 | tail 10u32 | e u32 | f u32 | name[43]
        # 回复 0x7172 recv_msma_equipset_store_r（处理器 0xAB5F0A，size 0x8C）：
        #   result i32 | uniqid u64 | 同一个 121B 装备组块 = 133B
        #   0xAB5FD8 会校验「游标 == end」，长度必须精确。
        body = rest
        need = 8 + EQUIPSET_WIRE_SIZE
        if len(body) < need:
            log('  [hangar] 0x9527 正文只有 %d 字节（需要 %d），忽略' % (len(body), need))
            return []
        uniqid = struct.unpack_from('<Q', body, 0)[0]
        blob = body[8:8 + EQUIPSET_WIRE_SIZE]
        store = HANGAR_EXPERIMENT_STORE if HANGAR_EXPERIMENT else HANGAR_STORE
        try:
            stored, entry = hangar_experiment.store_equipset(
                store, account, pilot_id, uniqid, blob)
        except ValueError as error:
            log('  [hangar] 装备记忆被拒绝: %s' % error)
            return [(0x7172, struct.pack('<iQ', -1, uniqid) + blob)]
        log('  [hangar] 装备记忆 slot=%d name=%r weapons=%s shield=%d'
            % (entry['slot'], entry['name'], entry['weapons'], entry['shield']))
        return [(0x7172, equipset_store_reply_body(uniqid, stored))]
    if op == 0x9A9D:
        # 0x9A9D send_msma_msset_get（发送端 0xAE4D99），正文空。
        # 回 0x356F recv_msma_msset_get_r（处理器 0xAABFB0，reserve 0x784=1924）：
        #   u32 count（0xAAC028 `cmp ebx,0x14` ⇒ 最多 20）
        #   count × 95B 机体组块（反序列化器 0xA96600）
        # 4 + 20×96 = 1924 正好是那个 reserve。
        store = HANGAR_EXPERIMENT_STORE if HANGAR_EXPERIMENT else HANGAR_STORE
        sets = hangar_experiment.msset_list(store, account, pilot_id)
        return [(0x356F, msset_list_body(sets))]
    if op == 0xA76E:
        # 0xA76E send_msma_msset_store（发送端 0xAE4ED0，`push 0x62`）：
        # 「将吉姆加入 机体设置01 的机体组」按钮。正文 95B = 机体组块，
        #   序列化器 0xA94770：u64 | u16 编号 | u16 槽位 | char[43] 名字 |
        #                     4×u64 机体 uniqid | 4×u16
        # 回 0xB8BB recv_msma_msset_store_r（处理器 0xAC3EF8，`push 0x64`）：
        #   result i32 | 同一个 95B 块 = 99B（0xAC3F9B 校验游标==end）
        if len(rest) < MSSET_WIRE_SIZE:
            log('  [hangar] 0xA76E 正文只有 %d 字节（需要 %d），忽略'
                % (len(rest), MSSET_WIRE_SIZE))
            return []
        blob = rest[:MSSET_WIRE_SIZE]
        store = HANGAR_EXPERIMENT_STORE if HANGAR_EXPERIMENT else HANGAR_STORE
        try:
            stored, entry = hangar_experiment.store_msset(store, account, pilot_id, blob)
        except ValueError as error:
            log('  [hangar] 机体组保存被拒绝: %s' % error)
            return [(0xB8BB, struct.pack('<i', -1) + blob)]
        log('  [hangar] 机体组 保存 index=%d slot=%d name=%r ms=%s'
            % (entry['index'], entry['slot'], entry['name'],
               [m for m in entry['ms'] if m]))
        return [(0xB8BB, msset_store_reply_body(stored))]
    one = hall_reply(op, rest, account)
    return [one] if one else []


def msset_list_body(sets, limit=MSSET_MAX_COUNT):
    """0x356F msma_msset_get_r 的正文：u32 count + count×95B。"""
    items = list(sets)[:limit]
    return (struct.pack('<I', len(items))
            + b''.join(encode_msset(entry) for entry in items))


def msset_store_reply_body(blob, result=0):
    """0xB8BB msma_msset_store_r 的正文（99B = result i32 + 95B 块）。"""
    if len(blob) != MSSET_WIRE_SIZE:
        raise ValueError('msset block must be %d bytes' % MSSET_WIRE_SIZE)
    return struct.pack('<i', result) + blob


def equipset_store_reply_body(uniqid, blob, result=0):
    """0x7172 msma_equipset_store_r 的正文（133B）。

    处理器 0xAB5F0A：0xAB5F41 claim_u32+read_u32(result) →
    0xAB5F8C claim 8+read_u64(uniqid) → 0xAB5FB9 claim(0x80 内存块)+0xA96750
    读 121B 装备组 → 0xAB5FD8 游标必须等于 end。
    4 + 8 + 121 = 133。
    """
    if len(blob) != EQUIPSET_WIRE_SIZE:
        raise ValueError('equipset block must be %d bytes' % EQUIPSET_WIRE_SIZE)
    return struct.pack('<iQ', result, uniqid & 0xffffffffffffffff) + blob


UNLOCK_REPLY_OVERRIDE = True   # 单元测试置 False，避免受调试用覆盖文件影响


def unlock_reply_body(uniqid, item_id, db_index, result=0):
    """0x45E4 msma_weapon_unlock_r 的正文（17B）。

    处理器 = 0xAAE0B5（`cmp eax,0x45E4` 在 0xAAE0AA，日志串 0xE10738
    "recv_msma_weapon_unlock_r"）。读取序列逐条对照原语宽度：

      0xAAE0FD  0xA5A270 claim_u32 + 0xA5A310 read_u32   → result   u32   4B
      0xAAE134  0xA94620 claim 8   + 0xA5D7C0 read_u64   → uniqid_ms u64  8B
      0xAAE174  0xA5A270 claim_u32 + 0xA5A310 read_u32   → item_id  u32   4B
      0xAAE198  0xA5D400 claim 1   + 0xA5A360 read_u8    → db_index s8    1B
                                                          -------------------
                                                                   17B

    两个独立佐证：
      ① 0xAAE0D1 `push 0x11; call session->vt[0x78]` —— 和四个 send 函数里
         `push 0x16/0x12` 是同一方法（申请定长正文），0x11 = 17 与字段和在字节上吻合。
      ② 0xAAE1BC `mov eax,[esp+0x14]; cmp eax,[esp+0x18]; jne error(0x110,1)`
         拿游标和 end 比 —— **正文必须被恰好读完**，多一字节也静默走 error 分支。
    另外 0xA63160 用 `movsx` 打印 db_index ⇒ 该字段是有符号单字节。

    调试用：若存在 server/unlock_reply_override.hex，则用它替换正文
    （支持 {uniqid}/{item_id}/{db_index8}/{db_index} 占位，各自展开成小端 hex），
    这样可以不重启服务端就试不同布局。
    """
    override = os.path.join(HERE, 'unlock_reply_override.hex')
    if UNLOCK_REPLY_OVERRIDE and os.path.exists(override):
        try:
            text = open(override, encoding='utf-8').read()
            text = ''.join(line.split('#', 1)[0] for line in text.splitlines())
            text = (text.replace('{uniqid}', struct.pack('<Q', uniqid).hex())
                        .replace('{item_id}', struct.pack('<I', item_id).hex())
                        .replace('{db_index8}', ('%02x' % (db_index & 0xff)))
                        .replace('{db_index}', struct.pack('<I', db_index).hex()))
            return bytes.fromhex(''.join(text.split()))
        except Exception as error:  # 覆盖文件坏了就退回默认布局
            log('  [hangar] unlock_reply_override.hex 读取失败: %s' % error)
    return struct.pack('<IQIB', result & 0xffffffff, uniqid & 0xffffffffffffffff,
                       item_id & 0xffffffff, db_index & 0xff)


def channel_login_body(channel_id=1, pilot_id=1):
    """0xFB85。当前客户端字段与参考文档一致，host 上限 0x81，otp 上限 0x29。"""
    zone = load_local_zone()
    return ((0).to_bytes(4, 'little')
            + (channel_id & 0xFFFFFFFF).to_bytes(4, 'little')
            + _cstr(zone['host'], 0x81, 'ascii')
            + (zone['port'] & 0xFFFFFFFF).to_bytes(4, 'little')
            + (1).to_bytes(4, 'little')
            + (pilot_id & 0xFFFFFFFF).to_bytes(4, 'little')
            + _cstr(LOUNGE_OTP, 0x29, 'ascii'))


def saved_pilot_list_body(account):
    slots = saved_pilot_records(account)
    if not any(slots.values()):
        return None
    eff = (list_entry_from_create(slots[0]) if slots[0]
           else pilot_entry_vacant(0, avatar_id=1))
    zeon = (list_entry_from_create(slots[1]) if slots[1]
            else pilot_entry_vacant(1, avatar_id=17))
    return pilot_body(0, eff, zeon, 0, 0)


def pilot_entry_vacant(troops=0, avatar_id=1, gender=0):
    """一条可安全交给 UI 回调的“空槽”记录。

    本 build 固定解析 eff/zeon 各一条 398B 记录，不能省略第二条。全 0 虽然在线格式上
    可读，但业务回调仍会处理其 avatar，avatar_id=0 会进入未初始化的外观路径。
    空槽应以 pilot_id=0 表示“无人”，同时保留该阵营一套真实、可查询的默认外观。
    """
    return pilot_entry_real(
        pid=0, name='', troops=troops, level=0,
        avatar_id=avatar_id, gender=gender,
    )


def probe_candidates(args):
    """候选操作码列表：--probe-opcodes 显式给，或 --probe-range lo-hi [step]。"""
    out = []
    if args.probe_opcodes:
        for x in args.probe_opcodes.replace(';', ',').split(','):
            x = x.strip()
            if x:
                out.append(int(x, 16) if x.lower().startswith('0x') else int(x))
    if args.probe_range:
        lo, _, hi = args.probe_range.partition('-')
        lo = int(lo, 16) if lo.lower().startswith('0x') else int(lo)
        hi = int(hi, 16) if hi.lower().startswith('0x') else int(hi)
        step = max(1, args.probe_step)
        out.extend(range(lo, hi + 1, step))
    seen = set()
    uniq = []
    for v in out:
        if 0 <= v <= 0xFFFF and v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


def missing_body(name, mode=None):
    """解密包里没有这张表时，回什么正文。

    `####\n`（纯注释、0 行数据）实测不行：客户端不再要第三张表。
    怀疑表加载器按行下标取数，0 行直接越界（异常被 0x544790 的 SEH 吞掉）。
    所以默认改成"有行有列"的占位宽表：
      · 第一行是 # 开头的列名（真实 CSV 的头也是 # 开头，会被跳过）
      · 之后 24 行、40 列，第一列唯一（索引表的主键列通常在第一列）
      · 其余全是 0（数字列、字符串列都能吃）
    """
    mode = mode or (MISSING_BODY[0] or 'wide')
    if mode == 'empty':
        return b''
    if mode == 'comment':
        return b'####\n'
    if mode.startswith('cols='):
        # 只改列数做单变量实验：cols=8 → 8 列 ×24 行
        ncol = max(1, int(mode.split('=', 1)[1]))
        nrow = 24
        out = ['#' + ','.join('COL%d' % i for i in range(ncol))]
        for r in range(1, nrow + 1):
            out.append(str(r) + ',' + ','.join(['0'] * (ncol - 1)))
        return ('\r\n'.join(out) + '\r\n').encode('utf-8')
    if mode == 'autoexec':
        alt = os.path.join(HERE, '..', 'GundamOnline_CHINA_已解密',
                           'decrypted', 'settings', 'autoexec.cfg')
        alt = os.path.normpath(alt)
        if os.path.isfile(alt):
            return open(alt, 'rb').read()
        return b'####\n'
    ncol, nrow = 40, 24
    if mode.endswith('-big'):
        nrow = 100   # ~10KB，和 autoexec 的 10222 字节同量级
    out = ['#' + ','.join('COL%d' % i for i in range(ncol))]
    for r in range(1, nrow + 1):
        row = ['0'] * ncol
        row[0] = str(r)          # 主键列：唯一
        # 第 4/5 列是枚举字符串（比较常量在 0xCB8770 一带）：
        #   4 = 武器组类型 MAIN / EX / SUB1 / NONE
        #   5 = 部位      NONE / L_HAND / R_HAND / ACTIVE_WEAPON
        if ncol > 5:
            row[4] = SET_TYPE[0]
            row[5] = SET_PART[0]
        # 第 28 列是地区标签（"ALL"/"CHINA"/"JAPAN"）
        if ncol > 28:
            row[28] = REGION[0]
        out.append(','.join(row))
    blob = ('\r\n'.join(out) + '\r\n').encode('utf-8')
    if mode.endswith('-big'):
        target = 10222            # 和 autoexec.cfg 完全一样长
        if len(blob) < target:
            blob += b'#' * (target - len(blob))
    return blob


def datafile_block(name, data, result=0):
    """0x5290，recv_datafile_download_r。

    u32 结果、文件名、hash、原始字节数、u16 压缩标记、u32 正文字节数、正文。
    压缩标记 0。正文按文本读，并且会先丢掉前 2 字节。
    短于 3 字节时丢掉之后是空的，这一项失败，队列停住，
    空闲掐线就是 L 2:0。没有原文的表回一行注释，丢掉 2 字节后仍以 # 开头。
    """
    raw = name.encode('ascii', 'replace')
    if len(raw) >= 0x100:
        raw = raw[:0xFF]
    if not data:
        data = missing_body(name)
    body = (((result or 0) & 0xFFFFFFFF).to_bytes(4, 'little')
            + raw + b'\x00'
            + (0).to_bytes(4, 'little')
            + len(data).to_bytes(4, 'little')
            + (0).to_bytes(2, 'little')
            + len(data).to_bytes(4, 'little')
            + data)
    return _align_message(_kind0((0x5290).to_bytes(2, 'little') + body)).hex()


def overplay_ok_block(seconds=0):
    """0x4F3F，回答 0x3B8F（send_overplay_resettime_get）。

    确定按钮走的是这条，不是选区。u32 <= 0 时 0x9E81A0 关掉选择世界窗口。
    正数会被当成剩余秒数，弹出防沉迷提示。
    """
    body = (0x4F3F).to_bytes(2, 'little') + (seconds & 0xFFFFFFFF).to_bytes(4, 'little')
    msg = bytes([0x00, len(body)]) + body
    pad = bytes([0x00, 0x06, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00])
    plain = msg + pad
    if len(plain) != 16:
        raise RuntimeError('overplay plain %d' % len(plain))
    return plain.hex()


def _cstr(text, limit, enc='utf-8'):
    """0xA5A160 只读到第一个 0，上限是 limit。后面的 0 不会被跳过。"""
    raw = text.encode(enc, 'replace')
    if len(raw) >= limit:
        raw = raw[:limit - 1]
    return raw + b'\x00'


def worldlist_select_r(name=None, host=None):
    """0x1146，回答 0xA380（send_worldlist_select）。

    三个字符串是 C 字符串，上限分别是 0x31、0x81、0x29，不是定长。
    声明的载荷长度必须正好等于读到的字节，否则 0xA5B6B6 对不上结尾。
    字段顺序：结果码、英文区名、休息室地址、休息室端口、用户号、otp。
    结果码 0 会关掉认证连接，客户端接着连休息室。端口填 0 时这一步失败，
    画面闪白退回账密。
    """
    zone = load_local_zone()
    if name is None:
        name = zone['name']
    if host is None:
        host = zone['host']
    body = ((0).to_bytes(4, 'little')
            + _cstr(name, 0x31)
            + _cstr(host, 0x81, 'ascii')
            + (zone['port'] & 0xFFFFFFFF).to_bytes(4, 'little')
            + (zone['id'] & 0xFFFFFFFF).to_bytes(4, 'little')
            + _cstr('local', 0x29, 'ascii'))
    payload = (0x1146).to_bytes(2, 'little') + body
    if not 2 <= len(payload) <= 255:
        raise RuntimeError('select payload %d' % len(payload))
    msg = bytes([0x00, len(payload)]) + payload
    gap = (-len(msg)) % 16
    if gap:
        # 队尾必须是完整消息。最短的未知操作码是 4 字节。
        if gap < 4:
            extra = 4 - gap
            body = body[:-1] + (b'.' * extra) + b'\x00'
            payload = (0x1146).to_bytes(2, 'little') + body
            msg = bytes([0x00, len(payload)]) + payload
            gap = (-len(msg)) % 16
        dummy_len = gap - 2
        msg += bytes([0x00, dummy_len, 0xFF, 0xFF]) + b'\x00' * (dummy_len - 2)
    if len(msg) % 16:
        raise RuntimeError('select plain %d' % len(msg))
    return msg.hex()


def camellia_ecb(key, data):
    """用 openssl CLI 做 Camellia-128-ECB 加密（无填充，长度须为 16 的倍数）。"""
    p = subprocess.run(
        ['openssl', 'enc', '-camellia-128-ecb', '-K', key.hex(), '-nopad'],
        input=data, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError('openssl 失败: ' + p.stderr.decode('utf-8', 'replace')[:120])
    return p.stdout


def ct_mask(key16, n):
    """第 n 次（0 基）加解密调用时，明文前 4 字节要 XOR 的掩码。

    客户端递增 Camellia 上下文的首个 dword，掩码是
    `当前 dword ^ 初始 dword`（按大端字节序）。旧实现只修改偏移 3，
    在低字节不进位时碰巧正确；固定下行密钥 11*16 在 n=239 时发生
    进位，此后偏移 2 也必须参与 XOR。
    """
    base = int.from_bytes(key16[:4], 'big')
    current = (base + n) & 0xFFFFFFFF
    return (current ^ base).to_bytes(4, 'big')


def apply_ct_mask(buf, offset, key16, n):
    mask = ct_mask(key16, n)
    for j in range(4):
        buf[offset + j] ^= mask[j]


def camellia_block(key16, data, n):
    b = bytearray(data)
    apply_ct_mask(b, 0, key16, n)
    return camellia_ecb(key16, bytes(b))


def camellia_dec_block(key16, block, n):
    """Camellia-128-ECB 解密，再把首 dword 的计数器掩码 XOR 回去。"""
    p = subprocess.run(
        ['openssl', 'enc', '-d', '-camellia-128-ecb', '-K', key16.hex(), '-nopad'],
        input=block, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError('openssl 解密失败: ' + p.stderr.decode('utf-8', 'replace')[:120])
    b = bytearray(p.stdout)
    if len(b) != 16:
        raise RuntimeError('解密长度 %d' % len(b))
    apply_ct_mask(b, 0, key16, n)
    return bytes(b)


def decrypt_uplink(keymat, ct, n0):
    """上行密钥是握手材料的后 16 字节。n0 是本连接已经用过的上行调用次数。"""
    key = keymat[16:32]
    out = b''
    n = n0
    for i in range(0, len(ct), 16):
        out += camellia_dec_block(key, ct[i:i + 16], n)
        n += 1
    return out, n


def _cstrs(buf):
    parts = []
    while buf:
        z = buf.find(0)
        if z < 0:
            parts.append(buf)
            break
        parts.append(buf[:z])
        buf = buf[z + 1:]
    return parts


def describe_plain(pt):
    """拆开类型 0 的明文，日志里直接给出操作码和字符串。"""
    lines = []
    i = 0
    while i + 2 <= len(pt):
        if (pt[i] >> 4) != 0 or (pt[i] & 3) != 0:
            lines.append('  偏移 %d 起不是类型0: %s' % (i, pt[i:].hex()))
            break
        ln = pt[i + 1]
        total = 2 + ln
        if i + total > len(pt):
            lines.append('  偏移 %d 头不完整，声明长 %d' % (i, ln))
            break
        payload = pt[i + 2:i + total]
        if len(payload) >= 2:
            op = int.from_bytes(payload[:2], 'little')
            rest = payload[2:]
            extra = ''
            if op == 0xF24B:
                strs = [s.decode('ascii', 'replace') for s in _cstrs(rest) if s]
                extra = ' 字段=' + ' | '.join(strs)
            elif len(rest) == 4:
                extra = ' u32=%d' % int.from_bytes(rest, 'little', signed=True)
            elif rest.strip(b'\x00'):
                extra = ' 余=' + rest.hex()
            lines.append('  消息 操作码=%04x 载荷=%d%s' % (op, ln, extra))
        else:
            lines.append('  消息 载荷过短 %s' % payload.hex())
        i += total
    return '\n'.join(lines) if lines else '  (空)'


def camellia_evolve(key16, data):
    """分块加密；第 i 块用第 n0+i 次的计数器（n0 由 build_inbound_frames 传）。"""
    out = b''
    for i in range(0, len(data), 16):
        out += camellia_block(key16, data[i:i + 16], i // 16)
    return out


def pad16(b):
    r = len(b) % 16
    return b + (b'\x00' * (16 - r) if r else b'')


def cipher_size(plain_len):
    """上行帧的 u32 是补块前的明文长度，密文再对齐到 16。

    16 和 96 这类已经对齐的包看不出差别。0x8288 的明文只有 4 字节
    （00 02 88 82），线上却是 `04 00 00 00` + 16 字节密文。
    按密文长度去读会把后面的密文当成下一帧的长度，然后把连接掐掉。
    """
    if plain_len <= 0 or plain_len > 65535:
        return None
    return (plain_len + 15) & ~15


PACE = {'chunk': 0, 'gap': 0.0}   # --pace 字节 / --pace-gap 毫秒


def send_paced(conn, data):
    """按 PACE 分段慢发。为了验证"客户端是否按流拼包"：
    一次 sendall 一整条 10KB 消息会被 TCP 拆段，若客户端假设"一次读到一条消息"就会错位。"""
    if PACE['chunk'] <= 0 or len(data) <= PACE['chunk']:
        conn.sendall(data)
        return
    for i in range(0, len(data), PACE['chunk']):
        conn.sendall(data[i:i + PACE['chunk']])
        if PACE['gap'] > 0:
            time.sleep(PACE['gap'])


def send_downlink(conn, keymat, n0, plain, limit=16320):
    """把一条已经 16 字节对齐的明文拆成若干外层帧。

    每帧声明的长度等于该段明文长度。单帧不超过 16320，避免触发
    16366 字节的连接上限；段边界保持 16 字节对齐，因此声明长度和密文长度相同。
    """
    if len(plain) % 16:
        raise RuntimeError('downlink plain %d' % len(plain))
    key = keymat[:16]
    n = n0
    out = b''
    for off in range(0, len(plain), limit):
        chunk = plain[off:off + limit]
        buf = bytearray(chunk)
        for i in range(0, len(buf), 16):
            apply_ct_mask(buf, i, key, n)
            n += 1
        out += len(chunk).to_bytes(4, 'little') + camellia_ecb(key, bytes(buf))
        send_paced(conn, out)
        out = b''
        if off + limit < len(plain):
            time.sleep(0.05)
    return n


def build_inbound_frames(keymat, plains, n0=0):
    """keymat = 32 字节；下行（服务端→客户端）用前 16 字节。

    外层：u32 LE 密文长度 + 密文
    内层：u8 flag(0=明文) | u32 LE **整帧总长**(含 5 字节头) | payload
    n0 = 本连接里这是第几次下行解密调用（决定 counter）。
    """
    key = keymat[:16]
    out = b''
    n = n0
    for ph in plains:
        pt = pad16(bytes.fromhex(ph))
        buf = bytearray(pt)
        for i in range(0, len(buf), 16):
            apply_ct_mask(buf, i, key, n)
            n += 1
        ct = camellia_ecb(key, bytes(buf))
        out += len(ct).to_bytes(4, 'little') + bytes(ct)
    return out


def log(msg):
    line = time.strftime('%H:%M:%S ') + msg
    print(line, flush=True)
    with open(LOG, 'a', encoding='utf-8') as f:
        f.write(line + '\n')


def hexdump(b):
    out = []
    for i in range(0, len(b), 16):
        chunk = b[i:i + 16]
        asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
        out.append('    %08x  %-47s  %s' % (i, chunk.hex(' '), asc))
    return '\n'.join(out)


def build_reply(variant, payload):
    if variant == 'none':
        return b''
    if variant == 'proto':
        # 握手必须回够 32 字节（内容无所谓）；用全零便于与历史密文对照
        return b'\x00' * 32
    if variant == 'keyhex':
        # 用 --keyhex 指定的 32 字节密钥材料（用来验证"上行/下行各用一半"）
        return bytes.fromhex(KEYHEX[0]) if KEYHEX[0] else b'\x00' * 32
    if variant == 'zeros32':
        return b'\x00' * 32
    if variant == 'zeros16':
        return b'\x00' * 16
    if variant == 'zeros64':
        return b'\x00' * 64
    if variant == 'ff32':
        return b'\xff' * 32
    if variant == 'echo32':
        c = (payload[:16] + b'\x00' * 16)[:16]
        return c + c
    if variant == 'echo':
        return payload
    if variant == 'rand32':
        r = random.Random(0x5A5A)
        return bytes(r.getrandbits(8) for _ in range(32))
    return b''


def sweep_sender(conn, keymat, args):
    """握手收到首帧后，**一条连接里连发**多个候选（间隔 --sweep-gap）。

    第 21 轮实测：`len=整帧总长`的正确帧**不会**让客户端秒断（存活到 30 秒超时，
    弹 A 2:0），所以现在可以一条连接里连续试多个内容假设。
    （之前 len=payload 长 的错帧会被秒断、后续候选发不出去，才改成一条一个。）
    """
    try:
        time.sleep(args.sweep_gap)
        n = 0
        for i, (name, pt) in enumerate(SWEEP):
            data = bytes.fromhex(pt)
            nb = n
            frames = build_inbound_frames(keymat, [pt], n0=n)
            n += len(pad16(data)) // 16
            log('  [sweep %d/%d] %-12s 明文=%s (起始调用序号 n=%d) → 帧 %d 字节:\n%s'
                % (i + 1, len(SWEEP), name, pt, nb, len(frames), hexdump(frames)))
            send_paced(conn, frames)
            if i + 1 < len(SWEEP):
                time.sleep(args.sweep_gap)
        log('  [sweep] %d 个候选已全部下发' % len(SWEEP))
    except Exception as e:
        log('  [sweep] 中断: %r' % (e,))


def handle(conn, addr, args, idx, variant):
    log('accept %s:%d   [连接 #%d 变体=%s]' % (addr[0], addr[1], idx, variant))
    t0 = time.time()
    total = b''
    stage = 0
    sent_frame = 0
    sweep_started = False
    consumed = 0
    frame_idx = 0
    n_down = 0
    n_up = 0
    login_replied = False
    files_this_round = 0
    account_name = ''
    selected_pilot_id = 1
    battle_session = None
    scene_transition_pending = False
    keymat = bytes.fromhex(KEYHEX[0]) if KEYHEX[0] else b'\x00' * 32
    conn.settimeout(args.idle)
    try:
        while True:
            if battle_session is not None and LOCAL_BATTLE is not None:
                for _rop, body in LOCAL_BATTLE.tick(battle_session):
                    pt = op_block(_rop, body)
                    frames = build_inbound_frames(keymat, [pt], n0=n_down)
                    n_down += len(bytes.fromhex(pt)) // 16
                    send_paced(conn, frames)
                    log('  [battle] countdown elapsed; reply 0x%04x bodylen=%d' % (_rop, len(body)))
            try:
                data = conn.recv(4096)
            except socket.timeout:
                if battle_session is not None and LOCAL_BATTLE is not None:
                    continue
                log('  recv timeout (%ds idle)' % args.idle)
                break
            if not data:
                log('  peer closed after %d bytes' % len(total))
                break
            total += data
            log('  recv %d bytes (累计 %d):\n%s' % (len(data), len(total), hexdump(data)))

            # 阶段 0：等握手 16 字节 → 回 32 字节
            if stage == 0 and len(total) >= 16:
                reply = build_reply(variant, total)
                stage = 1
                if reply:
                    send_paced(conn, reply)
                    log('  [stage0] sent %d bytes (%s):\n%s' % (len(reply), variant, hexdump(reply)))
                else:
                    log('  [stage0] no reply (variant=%s)' % variant)
                # 故意不 continue：万一握手和帧在同一次 recv 里到达，也要接着解析

            # 阶段 1：按帧解析（u32 LE 长度 + 数据），并**响应式**下发候选
            #
            # 第 25 轮实测：客户端是**请求-响应**模型，盲推给它的帧它多半不理。
            # 正确的节奏是：
            #   客户端首帧(flen=16) → 我们发候选#1 → 客户端回一个 ACK(flen=9)
            #   → 我们立刻发候选#2 → …
            # 那条 ACK 的明文是 `20 00 XX 00 <4字节> 00`，把 XX=00 时 4 字节换成
            # 我们发的 -10000 会原样出现在里面 —— 说明客户端确实读懂了 payload。
            if stage >= 1:
                buf = total[16 + consumed:]
                while len(buf) >= 4:
                    flen = int.from_bytes(buf[:4], 'little')
                    clen = cipher_size(flen)
                    if clen is None:
                        log('  [stage1] 帧长异常 %d，停止解析' % flen)
                        stage = 99
                        break
                    need = 4 + clen
                    if len(buf) < need:
                        break
                    frame = buf[:need]
                    buf = buf[need:]
                    consumed += need
                    frame_idx += 1
                    log('  [frame %d] 明文 %d / 密文 %d 字节: %s' % (frame_idx, flen, clen, frame.hex()))

                    plain = b''
                    if args.login_seq:
                        try:
                            full, n_up = decrypt_uplink(keymat, frame[4:], n_up)
                            plain = full[:flen]
                            log('  [plain] n 用到 %d\n%s' % (n_up, describe_plain(plain)))
                        except Exception as e:
                            log('  [plain] 解密失败: %r' % (e,))

                    if args.login_seq and not sweep_started:
                        sweep_started = True
                        frames = build_inbound_frames(keymat, [LOGIN_TRIGGER], n0=n_down)
                        n_down += 1
                        send_paced(conn, frames)
                        log('  [login] 下发 op_de24（n=%d）→ 帧 %d 字节:\n%s'
                            % (n_down - 1, len(frames), hexdump(frames)))
                    elif args.login_seq and HANGAR_EXPERIMENT and LOCAL_BATTLE is not None and (
                            battle_session is not None or (
                                parse_msg(plain)[0] == 0xF24B and
                                18 <= len(parse_msg(plain)[1] or b'') <= 58)):
                        # Auth/lounge/battle share the local listener and frame codec.
                        # Recognize battle's distinct identity body, never send lounge A5DA.
                        for _op, _rest in iter_type0(plain):
                            if _op == 0xFFFF:
                                continue
                            if _op == 0xF24B:
                                authenticated, replies = LOCAL_BATTLE.authenticate(_rest)
                                if authenticated is not None:
                                    battle_session = authenticated
                                    conn.settimeout(0.25)
                                log('  [battle] authenticate %s' % ('accepted' if authenticated else 'rejected'))
                            elif battle_session is not None:
                                replies = LOCAL_BATTLE.replies(battle_session, _op, _rest)
                            else:
                                replies = []
                            for _rop, body in replies:
                                pt = op_block(_rop, body)
                                frames = build_inbound_frames(keymat, [pt], n0=n_down)
                                n_down += len(bytes.fromhex(pt)) // 16
                                send_paced(conn, frames)
                                log('  [battle] reply 0x%04x bodylen=%d' % (_rop, len(body)))
                    elif args.login_seq and (not login_replied) and plain[:4] == b'\x00\x5e\x4b\xf2':
                        login_replied = True
                        _acct = account_from_login(parse_msg(plain)[1] or b'')
                        if _acct:
                            account_name = _acct
                            remember_auth_account(_acct)
                            log('  [login] 账号=%s' % account_name)
                        ok = login_ok_block(args.login_code)
                        frames = build_inbound_frames(keymat, [ok], n0=n_down)
                        n_down += 1
                        send_paced(conn, frames)
                        log('  [login] 收到 0xF24B，回 op_a5da code=%d（n=%d）→ 帧 %d 字节:\n%s'
                            % (args.login_code, n_down - 1, len(frames), hexdump(frames)))
                    elif args.login_seq and plain[:4] == b'\x00\x0c\x4b\xf2':
                        ident = lounge_identity(parse_msg(plain)[1] or b'')
                        if ident:
                            account_name = LOUNGE_SESSIONS.get(ident, '')
                            if account_name:
                                adopt_unbound_pilots(account_name)
                                log('  [login] 休息室凭据 user=%d otp=%s → 账号=%s'
                                    % (ident[0], ident[1], account_name))
                            else:
                                log('  [login] 休息室凭据 user=%d otp=%s 没有对应账号'
                                    % ident)
                        pt = lounge_ok_block(0)
                        n_before = n_down
                        frames = build_inbound_frames(keymat, [pt], n0=n_down)
                        n_down += len(bytes.fromhex(pt)) // 16
                        send_paced(conn, frames)
                        log('  [login] 收到休息室 0xF24B，回 op_a5da code=0（n=%d）→ 帧 %d 字节'
                            % (n_before, len(frames)))
                    elif args.login_seq and parse_datafile_name(plain):
                        fname = parse_datafile_name(plain)
                        # 失败后客户端不换 TCP，从 autoexec 把整表再要一遍。
                        # 下行计数只增不减，和没读完的回复叠在一起，所以有的轮只过 2 张、
                        # 有的轮能走到 65 张。第二次见到 autoexec 就关掉，下一轮是新握手。
                        if fname.replace('\\', '/') == 'autoexec_sv.cfg' and files_this_round:
                            log('  [login] 又从 autoexec 重下（本轮已回 %d 张）。关掉连接'
                                % files_this_round)
                            stage = 99
                            break
                        if args.reply_delay > 0:
                            log('  [delay] %s 延迟 %.1fs 再回复' % (fname, args.reply_delay))
                            time.sleep(args.reply_delay)
                        src = _settings_file(fname)
                        experiment_body = ((xwar_entry.table_body(fname) or hangar_experiment.table_body(fname))
                                           if HANGAR_EXPERIMENT else None)
                        if experiment_body is not None:
                            data = experiment_body
                            tag = 'GM关联实验定义（非原始参数）'
                        elif src:
                            data = open(src, 'rb').read()
                            tag = os.path.basename(src)
                        else:
                            data = missing_body(fname)
                            tag = '缺表占位:%s %dB' % (MISSING_BODY[0], len(data))
                        _res = 0
                        if args.fail_at and (files_this_round + 1) == args.fail_at:
                            _res = args.fail_result
                            log('  [fail] 第 %d 张 %s 故意回 result=%d'
                                % (files_this_round + 1, fname, _res))
                        pt = datafile_block(fname, data, _res)
                        n_before = n_down
                        frames = build_inbound_frames(keymat, [pt], n0=n_down)
                        n_down += len(bytes.fromhex(pt)) // 16
                        send_paced(conn, frames)
                        # --dl-retry: repeat the SAME op_5290 body.
                        # Harmless on the client side (the handler looks the filepath up
                        # in the pump map and bails silently when it is gone), but it lets
                        # us distinguish "the body was rejected" from "the node was erased".
                        _reps = max(1, int(getattr(args, 'dl_retry', 1) or 1))
                        for _k in range(1, _reps):
                            time.sleep(max(0.0, float(getattr(args, 'dl_retry_gap', 1.0) or 0.0)))
                            frames = build_inbound_frames(keymat, [pt], n0=n_down)
                            n_down += len(bytes.fromhex(pt)) // 16
                            send_paced(conn, frames)
                            log('  [dl] 第 %d 张重发第 %d 次（%s）'
                                % (files_this_round + 1, _k + 1, fname))
                        files_this_round += 1
                        log('  [login] 收到 0xF86A %s，回 op_5290 正文 %d 字节（%s，n=%d..%d，本轮第 %d 张）'
                            % (fname, len(data), tag, n_before, n_down - 1, files_this_round))
                    elif args.login_seq and parse_msg(plain)[0] == 0x60CD:
                        # 表阶段之后客户端会发 send_pilot_list_get。
                        # 回复的操作码在镜像里找不到（分派是查表、表被壳处理过），
                        # 所以这里按候选列表逐条试探，外部探针同步读 [game+0x10615]。
                        _op, _rest = parse_msg(plain)
                        log('  [pilot] 收到 0x60CD send_pilot_list_get（正文 %d 字节）'
                            % len(_rest))
                        _saved = saved_pilot_list_body(account_name)
                        if _saved is not None:
                            pt = op_block(0xE13A, _saved)
                            n_before = n_down
                            frames = build_inbound_frames(keymat, [pt], n0=n_down)
                            n_down += len(bytes.fromhex(pt)) // 16
                            send_paced(conn, frames)
                            slots = saved_pilot_records(account_name)
                            names = []
                            for side, rec in slots.items():
                                if rec:
                                    names.append('%s:%s' % (
                                        'eff' if side == 0 else 'zeon',
                                        rec[4:29].split(b'\x00')[0].decode(
                                            'utf-8', 'replace')))
                            log('  [pilot] 回已保存机师 %s，op=0xe13a bodylen=%d n=%d..%d'
                                % (','.join(names), len(_saved), n_before, n_down - 1))
                            continue
                        if getattr(args, 'pilot_len_sweep', ''):
                            # 数据固定（real_eff），只改正文总长：验证"是不是长度差几字节"
                            spec = args.pilot_len_sweep
                            step = int(args.probe_len_step)
                            _lo, _, _hi = spec.partition('-')
                            lens = list(range(int(_lo, 0), int(_hi or _lo, 0) + 1, step)) \
                                if _hi else [int(_lo, 0)]
                            base = pilot_body(0, pilot_entry_real(1, 'TEST', 0), None, 0, 0)
                            log('  [pilot] 长度扫描 %s（数据固定 real_eff），间隔 %.2fs'
                                % (lens, args.probe_gap))
                            for _i, _L in enumerate(lens, 1):
                                body = (base + bytes(max(0, _L - len(base))))[: _L]
                                pt = op_block(0xE13A, body)
                                n_before = n_down
                                frames = build_inbound_frames(keymat, [pt], n0=n_down)
                                n_down += len(bytes.fromhex(pt)) // 16
                                send_paced(conn, frames)
                                log('  [len %d] %s bodylen=%d 帧头=%s'
                                    % (_i, time.strftime('%H:%M:%S'), len(body),
                                       bytes.fromhex(pt)[:5].hex()))
                                _t0 = time.time()
                                _stop = False
                                while time.time() - _t0 < max(0.5, args.probe_gap):
                                    _r, _, _ = select.select([conn], [], [], 0.2)
                                    if not _r:
                                        continue
                                    try:
                                        _pk = conn.recv(1, socket.MSG_PEEK)
                                    except Exception:  # noqa: BLE001
                                        _stop = True
                                        break
                                    if _pk == b'':
                                        log('  [len %d] >>> 对端关闭连接' % _i)
                                        _stop = True
                                        break
                                    if (_pk[0] >> 4) in (2, 3):
                                        # 类型2/3 = RTT/保活/控制帧，不是业务请求 → 忽略（不消费，留给接收循环）
                                        log('  [len %d] (保活帧 0x%02x，忽略，继续观察)' % (_i, _pk[0]))
                                        _rest = max(0.0, max(0.5, args.probe_gap) - (time.time() - _t0))
                                        if _rest > 0:
                                            time.sleep(_rest)
                                        break
                                    log('  [len %d] >>> 对端有新业务数据待读（被接受！首字节=0x%02x）'
                                        % (_i, _pk[0]))
                                    _stop = True
                                    break
                                if _stop:
                                    break
                            log('  [pilot] 长度扫描结束')
                            continue
                        if getattr(args, 'pilot_variants', ''):
                            names = [x.strip() for x in args.pilot_variants.split(',') if x.strip()]
                            log('  [pilot] 变体序列 %s，间隔 %.2fs（客户端不崩，纯服务端实验）'
                                % (names, args.probe_gap))
                            for _i, _nm in enumerate(names, 1):
                                if _nm not in PILOT_VARIANTS:
                                    log('  [var %d] 未知变体 %s，跳过' % (_i, _nm))
                                    continue
                                body = PILOT_VARIANTS[_nm]()
                                pt = op_block(0xE13A, body)
                                n_before = n_down
                                frames = build_inbound_frames(keymat, [pt], n0=n_down)
                                n_down += len(bytes.fromhex(pt)) // 16
                                send_paced(conn, frames)
                                log('  [var %d] %s %-6s op=0xe13a bodylen=%d 帧头=%s n=%d..%d'
                                    % (_i, time.strftime('%H:%M:%S'), _nm, len(body),
                                       bytes.fromhex(pt)[:5].hex(), n_before, n_down - 1))
                                # --pilot-repeat: resend the identical body (fixed length,
                                # no residue) to test "first copy swallowed by a stale
                                # pending-request object, second copy reaches the handler".
                                _reps = max(1, int(getattr(args, 'pilot_repeat', 1) or 1))
                                for _k in range(1, _reps):
                                    time.sleep(max(0.0, float(getattr(args, 'pilot_repeat_gap', 3.0) or 0.0)))
                                    _pt2 = op_block(0xE13A, body)
                                    _fr2 = build_inbound_frames(keymat, [_pt2], n0=n_down)
                                    n_down += len(bytes.fromhex(_pt2)) // 16
                                    send_paced(conn, _fr2)
                                    log('  [var %d] 重发第 %d 次（同正文 %d 字节）'
                                        % (_i, _k + 1, len(body)))
                                # 观察窗：不只知道"有没有反应"，还要分清是哪种
                                #   有新数据待读 -> 客户端追问（被接受）
                                #   EOF          -> 客户端断连（被拒/异常）
                                #   超时         -> 无反应
                                _t0 = time.time()
                                _closed = _pending = False
                                while time.time() - _t0 < max(0.5, args.probe_gap):
                                    _r, _, _ = select.select([conn], [], [], 0.25)
                                    if not _r:
                                        continue
                                    try:
                                        _pk = conn.recv(1, socket.MSG_PEEK)
                                    except Exception as _e:      # noqa: BLE001
                                        log('  [var %d] 对端异常 %s' % (_i, _e))
                                        _closed = True
                                        break
                                    if _pk == b'':
                                        log('  [var %d] >>> 对端在 %.1fs 后关闭连接（被拒/异常）'
                                            % (_i, time.time() - _t0))
                                        _closed = True
                                        break
                                    if (_pk[0] >> 4) in (2, 3):
                                        log('  [var %d] (保活帧 0x%02x，忽略，继续观察)' % (_i, _pk[0]))
                                        _rest = max(0.0, max(0.5, args.probe_gap) - (time.time() - _t0))
                                        if _rest > 0:
                                            time.sleep(_rest)
                                        break
                                    log('  [var %d] >>> 对端有新业务数据待读 +%.1fs'
                                        '（客户端追问=被接受！首字节=0x%02x）'
                                        % (_i, time.time() - _t0, _pk[0]))
                                    _pending = True
                                    break
                                else:
                                    log('  [var %d] 观察 %.0fs：无任何反应'
                                        % (_i, args.probe_gap))
                                if _closed:
                                    log('  [pilot] 后续变体不再发送')
                                    break
                                if _pending:
                                    log('  [pilot] 交给接收循环处理客户端的新请求')
                                    break
                            log('  [pilot] 变体跑完')
                            continue
                        cand = probe_candidates(args)
                        if not cand:
                            log('  [pilot] 没配置 --probe-opcodes / --probe-range，不回')
                        else:
                            lens = []
                            for x in str(args.probe_body_len).split(','):
                                x = x.strip()
                                if not x:
                                    continue
                                if '-' in x:
                                    _lo, _, _hi = x.partition('-')
                                    _lo = int(_lo, 0)
                                    _hi = int(_hi, 0)
                                    _st = max(1, args.probe_len_step)
                                    lens.extend(range(_lo, _hi + 1, _st))
                                else:
                                    lens.append(int(x, 0))
                            log('  [pilot] 开始试探 %d 个操作码 x %d 种正文长度 %s，间隔 %.2fs'
                                % (len(cand), len(lens), lens, args.probe_gap))
                            combos = []
                            if args.pilot_combos:
                                for c in args.pilot_combos.split(';'):
                                    c = c.strip()
                                    if c:
                                        a, _, b = c.partition(',')
                                        combos.append((int(a), int(b)))
                            if not combos:
                                combos = [(args.pilot_eff, args.pilot_zeon)]
                            log('  [pilot] 机师条数组合: %s' % combos)
                            k = 0
                            _ci = 0
                            kinds = []
                            for x in str(getattr(args, 'probe_kinds', '') or '').split(','):
                                x = x.strip()
                                if x:
                                    kinds.append(int(x, 0))
                            if not kinds:
                                kinds = [None]
                            log('  [pilot] 长度字段宽度候选 kinds=%s' % [str(v) if v is not None else 'auto' for v in kinds])
                            for op in cand:
                                for kd in kinds:
                                    for L in lens:
                                        k += 1
                                        if args.pilot_body and op == 0xE13A:
                                            _e, _z = combos[_ci % len(combos)]
                                            body = pilot_list_body(_e, _z, args.pilot_name)
                                        else:
                                            body = b'\x00' * max(0, L)
                                        pt = op_block(op, body, kind=kd)
                                        n_before = n_down
                                        frames = build_inbound_frames(keymat, [pt], n0=n_down)
                                        n_down += len(bytes.fromhex(pt)) // 16
                                        send_paced(conn, frames)
                                        log('  [probe %d] 帧头=%s 前16B=%s'
                                            % (k, bytes.fromhex(pt)[:4].hex(), bytes.fromhex(pt)[:16].hex()))
                                        log('  [probe %d] %s op=0x%04x kind=%s bodylen=%d eff,zeon=%s n=%d..%d'
                                            % (k, time.strftime('%H:%M:%S'), op,
                                               'auto' if kd is None else kd, len(body),
                                               combos[_ci % len(combos)] if (args.pilot_body and op == 0xE13A) else '-',
                                               n_before, n_down - 1))
                                        _ci += 1
                                        time.sleep(max(0.0, args.probe_gap))
                            log('  [pilot] 候选跑完')
                    elif args.login_seq and parse_msg(plain)[0] == 0xFD3E:
                        _op, _rest = parse_msg(plain)
                        if len(_rest) < CREATE_REQ_LEN:
                            log('  [create] 0xFD3E 正文 %d 字节，短于 %d，不回复'
                                % (len(_rest), CREATE_REQ_LEN))
                        else:
                            record, slot = _rest[:CREATE_REC_LEN], int.from_bytes(
                                _rest[CREATE_REC_LEN:CREATE_REQ_LEN], 'little')
                            stored = save_created_pilot(account_name, record, slot)
                            body = (0).to_bytes(4, 'little') + stored
                            pt = op_block(0xC43C, body)
                            n_before = n_down
                            frames = build_inbound_frames(keymat, [pt], n0=n_down)
                            n_down += len(bytes.fromhex(pt)) // 16
                            send_paced(conn, frames)
                            log('  [create] 保存机师 id=%d troops=%d slot=%d name=%s，'
                                '回 op_c43c bodylen=%d n=%d..%d'
                                % (int.from_bytes(stored[:4], 'little'), stored[29],
                                   slot, stored[4:29].split(b'\x00')[0].decode(
                                       'utf-8', 'replace'),
                                   len(body), n_before, n_down - 1))
                    elif args.login_seq and parse_msg(plain)[0] == 0xF705:
                        _op, _rest = parse_msg(plain)
                        troops = int.from_bytes(_rest[:4], 'little') if len(_rest) >= 4 else 0
                        pid = int.from_bytes(_rest[4:8], 'little') if len(_rest) >= 8 else 0
                        selected_pilot_id = pid
                        skip = _rest[8] if len(_rest) >= 9 else 0
                        body = pilot_select_body()
                        pt = bytes.fromhex(op_block(0x063E, body))
                        n_before = n_down
                        n_down = send_downlink(conn, keymat, n_down, pt)
                        log('  [select] 收到 0xF705 troops=%d pilot=%d skip=%d，'
                            '回 op_063e bodylen=%d，分 %d 帧，n=%d..%d'
                            % (troops, pid, skip, len(body),
                               (len(pt) + 16319) // 16320, n_before, n_down - 1))
                    elif args.login_seq and parse_msg(plain)[0] == 0x3E0B:
                        body = channel_list_body()
                        pt = op_block(0xF11C, body)
                        n_before = n_down
                        frames = build_inbound_frames(keymat, [pt], n0=n_down)
                        n_down += len(bytes.fromhex(pt)) // 16
                        send_paced(conn, frames)
                        log('  [channel] 收到 0x3E0B，回 op_f11c 1 条频道，'
                            'scene=%d bodylen=%d n=%d..%d'
                            % (body[4 + 41], len(body), n_before, n_down - 1))
                    elif args.login_seq and parse_msg(plain)[0] == 0x2830:
                        _op, _rest = parse_msg(plain)
                        channel_id = int.from_bytes(_rest[:4], 'little') if len(_rest) >= 4 else 1
                        body = channel_login_body(channel_id, 1)
                        pt = op_block(0xFB85, body)
                        n_before = n_down
                        frames = build_inbound_frames(keymat, [pt], n0=n_down)
                        n_down += len(bytes.fromhex(pt)) // 16
                        send_paced(conn, frames)
                        log('  [channel] 收到 0x2830 channel=%d，回 op_fb85 %s:%d pilot=%d n=%d..%d'
                            % (channel_id, load_local_zone()['host'],
                               load_local_zone()['port'], 1, n_before, n_down - 1))
                    elif args.login_seq and iter_type0(plain) and any(
                            op in HALL_OPS or op in HALL_NO_REPLY_OPS
                            for op, _rest in iter_type0(plain)):
                        # 客户端会把多条请求塞进同一帧；其中还可能混有无需应答
                        # 或尚未实现的操作码。必须逐条处理，不能让其中一条拖掉整帧。
                        for _op, _rest in iter_type0(plain):
                            if _op == 0xC475:
                                scene_transition_pending = True
                            if _op in HALL_NO_REPLY_OPS:
                                log('  [hall] 收到 0x%04x（协议规定无需直接应答）' % _op)
                                continue
                            replied = hall_replies(_op, _rest, account_name, selected_pilot_id)
                            if not replied:
                                log('  [hall] 同帧未知/未实现 0x%04x（不影响其他请求）' % _op)
                                continue
                            for _rop, body in replied:
                                pt = op_block(_rop, body)
                                n_before = n_down
                                frames = build_inbound_frames(keymat, [pt], n0=n_down)
                                n_down += len(bytes.fromhex(pt)) // 16
                                send_paced(conn, frames)
                                log('  [hall] 收到 0x%04x，回占位 0x%04x bodylen=%d n=%d..%d'
                                    % (_op, _rop, len(body), n_before, n_down - 1))
                            if _op == 0xD377 and scene_transition_pending:
                                # 占位场景脚本。客户端包内确实存在此测试脚本，它只写
                                # trace，不改账号/机师数据。以后应替换为真实大厅脚本名
                                # 及真实 val1/val2。正文：src NUL | u32 val1 | u32 val2。
                                script_body = (b'test_lobby_scr_0.nut\x00' + bytes(8))
                                pt = op_block(0xA64A, script_body)
                                n_before = n_down
                                frames = build_inbound_frames(keymat, [pt], n0=n_down)
                                n_down += len(bytes.fromhex(pt)) // 16
                                send_paced(conn, frames)
                                scene_transition_pending = False
                                log('  [hall] 场景切换后主动推占位 0xa64a '
                                    'src=test_lobby_scr_0.nut bodylen=%d n=%d..%d'
                                    % (len(script_body), n_before, n_down - 1))
                    elif args.login_seq and parse_msg(plain)[0] == 0xE139:
                        # 客户端在机师列表之后会要"扭蛋奖品阵容"
                        # （_proto_lounge_client::send_gacha_prize_lineup）。
                        # 先只记录，回复格式（0x3B34 recv_gacha_prize_lineup_r）待反推。
                        _op, _rest = parse_msg(plain)
                        log('  [gacha] 收到 0xE139 send_gacha_prize_lineup（载荷 %d 字节，%s）'
                            % (len(_rest), _rest[:8].hex()))
                    elif args.login_seq and parse_msg(plain)[0] == 0x70E9:
                        _op, _rest = parse_msg(plain)
                        body = body_70e9(_rest, args.seventye9)
                        if body is None:
                            log('  [70e9] 收到模块校验报告（正文 %d 字节，前 4 字节 %s）→ 按配置不回'
                                % (len(_rest), _rest[:4].hex()))
                        else:
                            pt = op_block(0x70E9, body)
                            n_before = n_down
                            frames = build_inbound_frames(keymat, [pt], n0=n_down)
                            n_down += len(bytes.fromhex(pt)) // 16
                            send_paced(conn, frames)
                            log('  [70e9] 收到模块校验报告（%d 字节）→ 回 op_70e9 %d 字节正文'
                                '（%s，n=%d..%d）' % (len(_rest), len(body), args.seventye9,
                                                     n_before, n_down - 1))
                    elif args.login_seq and plain[:4] == b'\x00\x02\x88\x82':
                        zone = load_local_zone()
                        pt = worldlist_get_r()
                        n_before = n_down
                        frames = build_inbound_frames(keymat, [pt], n0=n_down)
                        n_down += len(bytes.fromhex(pt)) // 16
                        send_paced(conn, frames)
                        log('  [login] 收到 0x8288，回 op_298e %s %s:%d（n=%d..%d）→ 帧 %d 字节'
                            % (zone['name'], zone['host'], zone['port'],
                               n_before, n_down - 1, len(frames)))
                    elif args.login_seq and plain[:4] == b'\x00\x02\x8f\x3b':
                        pt = overplay_ok_block(0)
                        n_before = n_down
                        frames = build_inbound_frames(keymat, [pt], n0=n_down)
                        n_down += len(bytes.fromhex(pt)) // 16
                        send_paced(conn, frames)
                        log('  [login] 收到 0x3B8F，回 op_4f3f 剩余时间 0（n=%d）→ 帧 %d 字节'
                            % (n_before, len(frames)))
                    elif args.login_seq and plain[:4] == b'\x00\x06\x80\xa3':
                        zone = load_local_zone()
                        bind_lounge_session(zone['id'], LOUNGE_OTP,
                                            account_name or AUTH_ACCOUNT['name'])
                        pt = worldlist_select_r()
                        n_before = n_down
                        frames = build_inbound_frames(keymat, [pt], n0=n_down)
                        n_down += len(bytes.fromhex(pt)) // 16
                        send_paced(conn, frames)
                        log('  [login] 收到 0xA380，回 op_1146 %s %s:%d（n=%d..%d）→ 帧 %d 字节'
                            % (zone['name'], zone['host'], zone['port'],
                               n_before, n_down - 1, len(frames)))
                    elif args.sweep and not args.login_seq and not sweep_started:
                        sweep_started = True
                        threading.Thread(target=sweep_sender,
                                         args=(conn, keymat, args), daemon=True).start()
                        log('  [sweep] 首帧已收到，排程 %d 个候选（间隔 %.1fs，定时连发）'
                            % (len(SWEEP), args.sweep_gap))
                    elif variant == 'proto' and sent_frame < args.echo_count:
                        sent_frame += 1
                        send_paced(conn, frame)
                        log('  [stage1] 回声第 %d 帧 (%d 字节)' % (sent_frame, len(frame)))
                    elif variant == 'keyhex' and INBOUND[0] and sent_frame == 0:
                        keymat = bytes.fromhex(KEYHEX[0]) if KEYHEX[0] else b'\x00' * 32
                        try:
                            frames = build_inbound_frames(keymat, INBOUND[0])
                        except Exception as e:
                            log('  [stage1] 造帧失败: %r' % (e,))
                            frames = b''
                        if frames:
                            sent_frame += 1
                            send_paced(conn, frames)
                            log('  [stage1] 伪造下行帧 %d 字节（密钥材料=%s）:\n%s'
                                % (len(frames), keymat.hex(), hexdump(frames)))
                    elif variant != 'proto':
                        pass
                if stage == 99:
                    break
    except Exception as e:
        log('  error: %r' % (e,))
    finally:
        if LOCAL_BATTLE is not None:
            LOCAL_BATTLE.disconnect(battle_session)
        try:
            conn.close()
        except Exception:
            pass
        log('  closed %s:%d (存活 %.1fs, 共收 %d 字节, 回声 %d 帧)'
            % (addr[0], addr[1], time.time() - t0, len(total), sent_frame))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, default=30000)
    ap.add_argument('--mode', default='proto',
                    help="proto / script / none / zeros16 / zeros32 / zeros64 / ff32 / echo32 / echo / rand32")
    ap.add_argument('--variants', default=','.join(DEFAULT_VARIANTS))
    ap.add_argument('--idle', type=int, default=30, help='读超时秒数')
    ap.add_argument('--echo-count', type=int, default=1, help='回声几帧（proto 模式）')
    ap.add_argument('--keyhex', default=None,
                    help='32 字节密钥材料 hex（keyhex 模式用；前 16 字节=下行密钥）')
    ap.add_argument('--inbound-pt', default=None,
                    help='逗号分隔的明文 hex，作为"服务端→客户端"帧发给客户端（keyhex 模式）')
    ap.add_argument('--sweep', action='store_true',
                    help='收到首帧后按间隔依次下发多个候选应答（默认候选见 DEFAULT_SWEEP）')
    ap.add_argument('--sweep-gap', type=float, default=8.0, help='候选间隔秒')
    ap.add_argument('--sweep-list', default=None,
                    help='覆盖候选：name=hex,name=hex（每个 hex 自动补零到 16 对齐）。给出则走旧的盲发，不回应登录包')
    ap.add_argument('--login-code', type=int, default=0,
                    help='收到 0xF24B 后，0xA5DA 里带回的 u32。>=0 推进到战区列表，<0 记为失败')
    ap.add_argument('--pace', type=int, default=0,
                    help='每条消息拆成多少字节一段发送（0=关闭）')
    ap.add_argument('--pace-gap', type=float, default=1.5,
                    help='段间隔毫秒')
    ap.add_argument('--reply-delay', type=float, default=0.0,
                    help='收到 0xF86A 后先等这么多秒再回复（用于给外部观察工具留窗口）')
    ap.add_argument('--missing-body', default='wide',
                    help='解密包里没有的表回什么正文。wide=40 列 ×24 行占位宽表（默认），'
                         'cols=N=指定列数（单变量实验用），comment=####\\n（已证不行），'
                         'autoexec=拿 autoexec.cfg 顶上')
    ap.add_argument('--fail-at', type=int, default=0,
                    help='让本轮第 N 张表的 0x5290 应答带非零 result（测客户端是否"跳过该表"）')
    ap.add_argument('--fail-result', type=int, default=1,
                    help='--fail-at 时用的 result 值（默认 1）')
    ap.add_argument('--probe-opcodes', default='',
                    help='收到 0x60CD 后逐条试探的候选操作码（逗号分隔，支持 0x）')
    ap.add_argument('--pilot-body', action='store_true',
                    help='对 0xE13A 用真实机师列表正文（而不是全零）')
    ap.add_argument('--pilot-eff', type=int, default=1, help='联邦侧机师条数')
    ap.add_argument('--pilot-zeon', type=int, default=1, help='吉翁侧机师条数')
    ap.add_argument('--pilot-combos', default='',
                    help='机师条数组合，如 "0,0;1,0;1,1"（每发一条换一个）')
    ap.add_argument('--pilot-len-sweep', default='',
                    help='收到 0x60CD 后按长度扫描发 real_eff 正文（lo-hi，步长 --probe-len-step）')
    ap.add_argument('--pilot-variants', default='',
                    help='收到 0x60CD 后连发的 0xE13A 正文变体，逗号分隔。'
                         '可选: ' + ','.join(PILOT_VARIANTS.keys()))
    ap.add_argument('--pilot-name', default='TEST', help='机师名（≤24 字符）')
    ap.add_argument('--probe-len-step', type=lambda s: int(s, 0), default=2,
                    help='--probe-body-len 用 lo-hi 形式时的步长')
    ap.add_argument('--probe-range', default='',
                    help='候选来自区间 lo-hi（含端点，支持 0x）')
    ap.add_argument('--probe-step', type=lambda s: int(s, 0), default=1,
                    help='区间步长，支持 0x 前缀')
    ap.add_argument('--probe-body-len', default='817',
                    help='试探正文长度（全零）。默认 817 = 本客户端 0xE13A 的空列表定长体')
    ap.add_argument('--probe-kinds', default='',
                    help='强制数据帧长度字段宽度 k（逗号列表，0=1B 1=2B 2=3B 3=4B）；'
                         '空=按长度自动。实测客户端对 k=1 只取低 8 位，>255 要靠 k=2/3 试')
    ap.add_argument('--dl-retry', type=int, default=1,
                    help='repeat each op_5290 datafile reply N times (default 1)')
    ap.add_argument('--dl-retry-gap', type=float, default=1.0,
                    help='seconds between datafile reply repeats')
    ap.add_argument('--pilot-repeat', type=int, default=1,
                    help='resend the same 0xE13A pilot body N times (default 1)')
    ap.add_argument('--pilot-repeat-gap', type=float, default=3.0,
                    help='seconds between pilot body repeats')
    ap.add_argument('--probe-gap', type=float, default=0.4,
                    help='两条试探之间的间隔秒数')
    ap.add_argument('--seventye9', '--70e9', dest='seventye9', default='none',
                    choices=['none', 'zero', 'ok4', 'mirror', 'echo'],
                    help='收到 0x70E9（CPS 模块校验报告）回什么：none=不回（默认，单向上报、'
                         '客户端没有这条的下行 handler），zero=3 个 0，ok4=1 个 0，'
                         'mirror=回显请求前 12 字节，echo=整段回显')
    ap.add_argument('--hangar-store', default=os.path.join(HERE, 'saved_hangar.json'),
                    help='角色机体资产JSON；缺省不授予机体，机型/武器ID须与客户端下载表匹配')
    ap.add_argument('--hangar-experiment', choices=['gm'], help='启用GM实验，资产写入独立的 .gm.json 存档')
    ap.add_argument('--battle-countdown', type=int, default=30,
                    help='本地正式战准备倒计时秒数（0..3600，默认30）')
    args = ap.parse_args()
    global HANGAR_STORE, HANGAR_EXPERIMENT, HANGAR_EXPERIMENT_STORE, LOCAL_BATTLE
    HANGAR_STORE = HangarStore(args.hangar_store)
    experiment_path = os.path.splitext(args.hangar_store)[0] + '.gm.json'
    HANGAR_EXPERIMENT_STORE = HangarStore(experiment_path)
    HANGAR_EXPERIMENT = args.hangar_experiment == 'gm'
    if HANGAR_EXPERIMENT:
        log('=== GM关联实验：msma_id=%d model_candidate=%d uniqid=%d；实验资产使用独立存档 ==='
            % (hangar_experiment.MSMA_ID, hangar_experiment.MODEL_ID, hangar_experiment.UNIQID))
    args.login_seq = bool(args.sweep and not args.sweep_list)
    PACE['chunk'] = args.pace
    PACE['gap'] = args.pace_gap / 1000.0
    if args.pace > 0:
        log('=== 分段慢发：每 %d 字节一段，间隔 %.1fms ===' % (args.pace, args.pace_gap))
    MISSING_BODY[0] = args.missing_body

    # 候选列表
    SWEEP.clear()
    if args.sweep_list:
        for item in args.sweep_list.split(','):
            item = item.strip()
            if not item:
                continue
            if '=' in item:
                n, h = item.split('=', 1)
                SWEEP.append((n.strip(), h.strip()))
            else:
                SWEEP.append(('c%d' % len(SWEEP), item))
    else:
        SWEEP.extend(DEFAULT_SWEEP)

    # sweep 模式默认给一组"前后半不同"的密钥，方便确认方向（前 16=下行）
    if args.sweep and not args.keyhex:
        args.keyhex = '11' * 16 + '22' * 16
        args.mode = 'keyhex'
    if args.sweep:
        args.mode = 'keyhex'

    KEYHEX[0] = args.keyhex
    INBOUND[0] = [x.strip() for x in args.inbound_pt.split(',') if x.strip()] if args.inbound_pt else []

    variants = [v.strip() for v in args.variants.split(',') if v.strip()]
    log('===== fake_auth start port=%d mode=%s echo_count=%d =====' % (args.port, args.mode, args.echo_count))
    if args.login_seq:
        log('登录序列：op_de24 → op_a5da code=%d → op_298e → 0x3B8F 回 op_4f3f → 0xA380 回 op_1146'
            % args.login_code)
        log('下行密钥材料 = %s（前 16=下行，后 16=上行）' % (args.keyhex,))
    elif args.sweep:
        log('sweep 候选 %d 个，间隔 %.1fs：%s'
            % (len(SWEEP), args.sweep_gap, ', '.join(n for n, _ in SWEEP)))
        log('下行密钥材料 = %s（前 16=下行，后 16=上行）' % (args.keyhex,))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', args.port))
    srv.listen(8)
    if HANGAR_EXPERIMENT:
        LOCAL_BATTLE = local_battle.LocalBattleBackend(
            xwar_entry.BOOKINGS, '127.0.0.1', srv.getsockname()[1], load_local_zone()['id'],
            user_id_for_account=lambda account: next(
                (ident[0] for ident, owner in LOUNGE_SESSIONS.items() if owner == account), 1),
            countdown_seconds=args.battle_countdown)
        LOCAL_BATTLE.units_for_pilot = HANGAR_EXPERIMENT_STORE.units
        log('[battle] local single-pilot preparation rooms enabled on the shared listener')
    log('listening 0.0.0.0:%d' % args.port)
    try:
        while True:
            conn, addr = srv.accept()
            with _lock:
                _conn_idx[0] += 1
                idx = _conn_idx[0]
            if args.mode == 'script':
                variant = variants[(idx - 1) % len(variants)]
            else:
                variant = args.mode
            threading.Thread(target=handle, args=(conn, addr, args, idx, variant), daemon=True).start()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
