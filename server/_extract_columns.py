# -*- coding: utf-8 -*-
"""从行解析器里抽取列布局：push <列号>; call 0xB081E0(整数) / 0xB082E0(字符串)。纯静态。"""
import json, struct, pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

IMG = 'server/img_dump/main_GundamOnline_CHINA.exe'
data = open(IMG, 'rb').read()
pe = pefile.PE(IMG, fast_load=True); BASE = pe.OPTIONAL_HEADER.ImageBase
SEC = [(s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData) for s in pe.sections]
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

def va2off(va):
    rva = va - BASE
    for sva, sz, raw in SEC:
        if sva <= rva < sva + sz:
            return raw + (rva - sva)

def code(va, n):
    o = va2off(va)
    return data[o:o+n] if o is not None else b''

GET_INT, GET_STR, ITER = 0xB081E0, 0xB082E0, 0xB08960

def fields_of(va, depth=2, seen=None):
    """返回 {列号: 'i'/'s'}；若是 Load 则先找到迭代器回调再进去。"""
    if seen is None: seen = set()
    if va in seen or depth < 0: return {}, None
    seen.add(va)
    buf = code(va, 0x300)
    if not buf: return {}, None
    ins = []
    for k in md.disasm(buf, va):
        ins.append(k)
        if k.mnemonic.startswith('ret'):
            break
    # 先看是不是 Load：找 call 0xB08960，取它前面的第 3 个 push imm
    for k, i in enumerate(ins):
        if i.mnemonic == 'call' and i.operands and i.operands[0].type == 2 and i.operands[0].imm == ITER:
            imms = [j.operands[0].imm for j in ins[:k]
                    if j.mnemonic == 'push' and j.operands and j.operands[0].type == 2]
            cb = imms[-3] if len(imms) >= 3 else None
            if cb:
                f, _ = fields_of(cb, depth - 1, seen)
                return f, cb
            return {}, None
    # 普通解析器（同时追踪寄存器里的常量：xor reg,reg / mov reg,imm）
    out = {}
    pending = None
    regs = {}
    for i in ins:
        m = i.mnemonic
        ops = i.operands
        if m == 'xor' and len(ops) >= 2 and ops[0].type == 1 and ops[1].type == 1 \
           and ops[0].reg == ops[1].reg:
            regs[ops[0].reg] = 0
            continue
        if m == 'mov' and len(ops) >= 2 and ops[0].type == 1 and ops[1].type == 2:
            regs[ops[0].reg] = ops[1].imm
            continue
        if m == 'push' and ops:
            if ops[0].type == 2:
                v = ops[0].imm
                if 0 <= v < 0x200:
                    pending = v
            elif ops[0].type == 1 and ops[0].reg in regs:
                v = regs[ops[0].reg]
                if 0 <= v < 0x200:
                    pending = v
        elif m == 'call' and ops and ops[0].type == 2:
            t = ops[0].imm
            if t == GET_INT and pending is not None:
                out.setdefault(pending, 'i')
            elif t == GET_STR and pending is not None:
                out.setdefault(pending, 's')
            pending = None
    # 再追一层直接调用（该表的子解析器），把它的列合并进来
    for i in ins:
        if i.mnemonic == 'call' and i.operands and i.operands[0].type == 2:
            t = i.operands[0].imm
            if 0x400000 < t < 0x2000000:
                f, _ = fields_of(t, depth - 1, seen)
                if f:
                    out.update(f)
    return out, None

rows = json.load(open('server/表解析器地址表.json'))
lines = ['# 各表列布局（自动抽取）', '',
         '> 由 `server/_extract_columns.py` 静态抽取：`push 列号; call 0xB081E0` = 整数列，',
         '> `call 0xB082E0` = 字符串列。列号是**原始 CSV 里的列序**（0 基，含被跳过的表头行不影响）。',
         '> 抽不到的说明解析器走的是更深的子函数，需要人工再追。', '',
         '| 表类 | 序号 | 解析入口 | 列数 | 整数列 | 字符串列 |', '|---|---|---|---|---|---|']
blank = 0
for cls, idx, load, cb in rows:
    ent = int(cb, 16) if cb else int(load, 16)
    f, via = fields_of(ent)
    if not f:
        blank += 1
        lines.append('| `%s` | %s | `%08X` | ? | - | - |' % (cls, idx, ent))
        continue
    mx = max(f) + 1
    ints = ','.join(str(k) for k in sorted(f) if f[k] == 'i')
    strs = ','.join(str(k) for k in sorted(f) if f[k] == 's')
    lines.append('| `%s` | %s | `%08X` | %d | %s | %s |' % (cls, idx, ent, mx, ints or '-', strs or '-'))
open('server/表列布局.md', 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
print('写出 server/表列布局.md，未抽出 %d / %d' % (blank, len(rows)))
