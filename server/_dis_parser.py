# -*- coding: utf-8 -*-
"""反汇编行解析器并在取字段处标注列号。用法: python server/_dis_parser.py 0x551BC0 [字数]"""
import sys, pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

IMG='server/img_dump/main_GundamOnline_CHINA.exe'
data=open(IMG,'rb').read()
pe=pefile.PE(IMG, fast_load=True); BASE=pe.OPTIONAL_HEADER.ImageBase
SEC=[(s.VirtualAddress, max(s.Misc_VirtualSize,s.SizeOfRawData), s.PointerToRawData) for s in pe.sections]
def va2off(va):
    rva=va-BASE
    for sva,sz,raw in SEC:
        if sva<=rva<sva+sz: return raw+(rva-sva)
GET_INT, GET_STR = 0xB081E0, 0xB082E0
md=Cs(CS_ARCH_X86, CS_MODE_32); md.detail=True

def run(va, limit=400, depth=0, label=''):
    o=va2off(va); buf=data[o:o+0x800]
    regs={}
    pending=None
    n=0
    print(' ' * depth + '=== %s %08X ===' % (label, va))
    subs=[]
    for i in md.disasm(buf, va):
        ann=''
        m, ops = i.mnemonic, i.operands
        if m=='xor' and len(ops)>=2 and ops[0].type==1 and ops[1].type==1 and ops[0].reg==ops[1].reg:
            regs[ops[0].reg]=0
        elif m=='mov' and len(ops)>=2 and ops[0].type==1 and ops[1].type==2:
            regs[ops[0].reg]=ops[1].imm
        elif m=='add' and len(ops)>=2 and ops[0].type==1 and ops[1].type==2:
            if ops[0].reg in regs: regs[ops[0].reg]+=ops[1].imm
        elif m=='sub' and len(ops)>=2 and ops[0].type==1 and ops[1].type==2:
            if ops[0].reg in regs: regs[ops[0].reg]-=ops[1].imm
        if m=='push' and ops:
            if ops[0].type==2:
                pending=ops[0].imm if 0<=ops[0].imm<0x400 else None
            elif ops[0].type==1 and ops[0].reg in regs and 0<=regs[ops[0].reg]<0x400:
                pending=regs[ops[0].reg]
        elif m=='call' and ops and ops[0].type==2:
            t=ops[0].imm
            if t==GET_INT:
                ann='   <== 取整数 列 %s' % pending
            elif t==GET_STR:
                ann='   <== 取字符串 列 %s' % pending
            elif BASE < t < 0x2000000 and t not in (0x4559C0,0xC11CCD,0xC11CCD,0xB08960):
                subs.append((t, i.address))
            pending=None
        if n < limit:
            print(' ' * depth + '%08X  %-22s %-7s %-28s%s' % (i.address, i.bytes.hex(), m, i.op_str, ann))
        n+=1
        if m.startswith('ret'):
            break
    for t,at in subs[:8]:
        run(t, limit, depth+2, 'sub from %08X' % at)

if __name__=='__main__':
    va=int(sys.argv[1],16)
    lim=int(sys.argv[2]) if len(sys.argv)>2 else 400
    run(va, lim)
