# -*- coding: utf-8 -*-
"""从解包镜像里批量抽"表规格"：每张表的列号 → 类型（整数/字符串/枚举），
枚举列还要把取值词表读出来。

做法（纯静态，不需要客户端）：
  1. 从 0x544E3C 的跳转表拿到 71 个 case 的表对象全局
  2. 每个表类的 vtable[0] = Load；Load 里 `call 0xB08960` 的第 3 个 push 是行回调；
     若第 0 槽本身就是"push 列号 → call 0xB081E0/0xB082E0"的直线代码，那它就是行解析器
  3. 行解析器里：`push <列号>; call 0xB081E0` = 整数列，`call 0xB082E0` = 字符串列
  4. 若某列取出来后马上 `call <helper>`，则把 helper 里所有"指向 C 字符串的立即数"
     当该列的枚举词表（例如 MAIN/EX/SUB1、CHINA/ALL/JAPAN）
  5. 追一层子解析器，把它的列合并进来（msma 系列就是这样）

输出：server/表规格.json、server/表规格.md
"""
import json
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM, X86_OP_REG

IMG = 'server/img_dump/main_GundamOnline_CHINA.exe'
data = open(IMG, 'rb').read()
pe = pefile.PE(IMG, fast_load=True)
BASE = pe.OPTIONAL_HEADER.ImageBase
SEC = [(s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData)
       for s in pe.sections]

GET_INT, GET_STR, ITER = 0xB081E0, 0xB082E0, 0xB08960

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True


def va2off(va):
    rva = va - BASE
    for sva, sz, raw in SEC:
        if sva <= rva < sva + sz:
            return raw + (rva - sva)
    return None


def code(va, n):
    o = va2off(va)
    return data[o:o + n] if o is not None else b''


def cstr(va):
    o = va2off(va)
    if o is None:
        return None
    e = data.find(b'\0', o)
    if e < 0 or e - o > 40:
        return None
    raw = data[o:e]
    if not raw or any(c < 0x20 or c > 0x7E for c in raw):
        return None
    return raw.decode('latin1')


def dis(va, n=0x300):
    """反汇编到第一个 ret 为止"""
    out = []
    for i in md.disasm(code(va, n), va):
        out.append(i)
        if i.mnemonic.startswith('ret'):
            break
    return out


def imm_strings(va, depth=1, seen=None):
    """收集函数里所有"立即数 → C 字符串"的字面量（只保留像枚举标识符的）"""
    if seen is None:
        seen = set()
    if va in seen or depth < 0:
        return []
    seen.add(va)
    res = []
    for i in dis(va, 0x400):
        if i.mnemonic in ('mov', 'push', 'cmp') and i.operands:
            for op in i.operands:
                if op.type == X86_OP_IMM:
                    s = cstr(op.imm)
                    if s and is_enum_token(s) and s not in res:
                        res.append(s)
    return res


def is_enum_token(s):
    """枚举取值长这样：MAIN / SUB1 / ACTIVE_WEAPON / NONE"""
    if not (2 <= len(s) <= 24):
        return False
    if not (s[0].isupper() or s[0] == '_'):
        return False
    return all(c.isupper() or c.isdigit() or c == '_' for c in s)


def fields_of(va, depth=2, seen=None, enums=None):
    """返回 {列号: 'i'/'s'} 和 {列号: [枚举词]}"""
    if enums is None:
        enums = {}
    if seen is None:
        seen = set()
    if va in seen or depth < 0:
        return {}, enums
    seen.add(va)
    ins = dis(va)
    if not ins:
        return {}, enums

    # 是 Load 吗？找 call 0xB08960，取它前面第 3 个 push imm
    for k, i in enumerate(ins):
        if i.mnemonic == 'call' and i.operands and i.operands[0].type == X86_OP_IMM \
                and i.operands[0].imm == ITER:
            imms = [j.operands[0].imm for j in ins[:k]
                    if j.mnemonic == 'push' and j.operands
                    and j.operands[0].type == X86_OP_IMM]
            if len(imms) >= 3:
                return fields_of(imms[-3], depth - 1, seen, enums)
            return {}, enums

    out = {}
    regs = {}
    pending = None
    last_col = None
    for i in ins:
        m, ops = i.mnemonic, i.operands
        if m == 'xor' and len(ops) >= 2 and ops[0].type == X86_OP_REG \
                and ops[1].type == X86_OP_REG and ops[0].reg == ops[1].reg:
            regs[ops[0].reg] = 0
            continue
        if m == 'mov' and len(ops) >= 2 and ops[0].type == X86_OP_REG \
                and ops[1].type == X86_OP_IMM:
            regs[ops[0].reg] = ops[1].imm
            continue
        if m == 'add' and len(ops) >= 2 and ops[0].type == X86_OP_REG \
                and ops[1].type == X86_OP_IMM and ops[0].reg in regs:
            regs[ops[0].reg] += ops[1].imm
            continue
        if m == 'push' and ops:
            if ops[0].type == X86_OP_IMM and 0 <= ops[0].imm < 0x200:
                pending = ops[0].imm
            elif ops[0].type == X86_OP_REG and ops[0].reg in regs \
                    and 0 <= regs[ops[0].reg] < 0x200:
                pending = regs[ops[0].reg]
            continue
        if m == 'call' and ops and ops[0].type == X86_OP_IMM:
            t = ops[0].imm
            if t == GET_INT and pending is not None:
                out.setdefault(pending, 'i')
                last_col = pending
                pending = None
            elif t == GET_STR and pending is not None:
                out.setdefault(pending, 's')
                last_col = pending
                pending = None
            else:
                # 取完某列紧接着调用的 helper，通常就是该列的枚举解析器
                if last_col is not None and BASE < t < 0x2000000:
                    ev = imm_strings(t, depth=1)
                    if len(ev) >= 2:
                        enums.setdefault(last_col, [])
                        for s in ev:
                            if s not in enums[last_col]:
                                enums[last_col].append(s)
                last_col = None
                pending = None

    # 追一层子解析器，把列合并进来
    for i in ins:
        if i.mnemonic == 'call' and i.operands and i.operands[0].type == X86_OP_IMM:
            t = i.operands[0].imm
            if 0x400000 < t < 0x2000000 and t not in (GET_INT, GET_STR, ITER, 0x4559C0):
                f, _ = fields_of(t, depth - 1, seen, enums)
                for k, v in f.items():
                    out.setdefault(k, v)
    return out, enums


def main():
    rows = json.load(open('server/表解析器地址表.json', encoding='utf-8'))
    spec = []
    for cls, idx, load, cb in rows:
        ent = int(cb, 16) if cb else int(load, 16)
        cols, enums = fields_of(ent)
        mx = (max(cols) + 1) if cols else 0
        spec.append({
            'class': cls,
            'idx': int(idx),
            'load': load,
            'entry': '%08X' % ent,
            'ncols_min': mx,
            'cols': {str(k): cols[k] for k in sorted(cols)},
            'enums': {str(k): v for k, v in sorted(enums.items()) if v},
        })
    json.dump(spec, open('server/表规格.json', 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)

    lines = ['# 表规格（自动抽取）', '',
             '> `ncols_min` 是**下界**（用寄存器传列号、在循环里递增的地方抓不到）。',
             '> `cols` 里 i = 整数列，s = 字符串列；`enums` 是枚举列的合法取值。', '',
             '| 表类 | 序号 | 入口 | ≥列数 | 整数列 | 字符串列 | 枚举列 |',
             '|---|---|---|---|---|---|---|']
    for s in sorted(spec, key=lambda x: x['idx']):
        ints = ','.join(k for k, v in s['cols'].items() if v == 'i')
        strs = ','.join(k for k, v in s['cols'].items() if v == 's')
        ens = '; '.join('%s:[%s]' % (k, '/'.join(v)) for k, v in s['enums'].items())
        lines.append('| `%s` | %d | `%s` | %d | %s | %s | %s |'
                     % (s['class'], s['idx'], s['entry'], s['ncols_min'],
                        ints or '-', strs or '-', ens or '-'))
    open('server/表规格.md', 'w', encoding='utf-8').write('\n'.join(lines) + '\n')

    n_enum = sum(1 for s in spec if s['enums'])
    print('表数 %d，抽到列的 %d，有枚举的 %d'
          % (len(spec), sum(1 for s in spec if s['ncols_min']), n_enum))


if __name__ == '__main__':
    sys.exit(main())
