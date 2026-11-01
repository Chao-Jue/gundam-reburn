#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""按 `0xBD1610` 的反汇编字面，重写客户端的分帧解码器，然后回读服务端实际发出的字节。

解码器（本机 v5.0.0.33 反汇编，`server/_dis_frame.txt`）：

    0xBD1610  sub esp,0x48
              ebx = 可用字节数 ; if (ebx < 1) return 0
              edi = buf
    0xBD1652  eax = buf[0]
              ecx = eax >> 4          ; type  (0..4 合法，>4 → 0xBD1A9A)
              jmp [ecx*4 + 0xBD1ADC]
    0xBD166A  eax &= 3                ; k = 长度字段宽度-1  （case 0 = 数据帧）
              if (ebx < k+2) return 0                    ; 头不够，等更多数据
              len  = buf[1]
              len += buf[2]<<8   (k>=1)
              len += buf[3]<<16  (k>=2)
              len += buf[4]<<24  (k>=3)
              total = len + k + 2                        ; 1(首字节) + (k+1) 长度字节 + len
              if (ebx < total) return 0                  ; 帧不完整，等
              vt[0x54](buf + k + 2, len)                 ; = 0xAA2D50 on_message
              return total

⇒ **长度字段 = 载荷长度（含 2 字节 opcode），不含首字节与长度字段自身。**

本脚本用来钉死一件事：我们 `fake_auth.op_block()` 发出去的字节流，
能不能被上面这个解码器**一帧不漏、一字节不剩**地吃掉。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server'))


def decode_stream(data: bytes):
    """严格照 0xBD1610 走；返回 [(total, type, k, len, payload)]。"""
    out = []
    i = 0
    n = len(data)
    while True:
        avail = n - i
        if avail < 1:
            break                                  # 0xBD1623  cmp ebx,1 / jb
        b0 = data[i]
        typ = b0 >> 4
        if typ > 4:
            raise ValueError(f'type={typ} > 4 @ {i}  → 走 0xBD1A9A')
        if typ != 0:
            out.append((None, typ, None, None, b''))
            break
        k = b0 & 3
        if avail < k + 2:                           # 0xBD166D
            break
        ln = data[i + 1]
        if k >= 1:
            ln |= data[i + 2] << 8
        if k >= 2:
            ln |= data[i + 3] << 16
        if k >= 3:
            ln |= data[i + 4] << 24
        total = ln + k + 2                          # 0xBD16A6
        if avail < total:                           # 0xBD16AA
            break
        payload = data[i + k + 2: i + k + 2 + ln]
        out.append((total, 0, k, ln, payload))
        i += total
    return out, i


def main() -> int:
    import fake_auth as fa

    cases = [
        ('0xE13A 正文 817（定案布局）', 0xE13A, fa.pilot_list_body()),
        ('0xE13A 正文 252（上轮的短 probe）', 0xE13A, b'\x00' * 252),
        ('0xE13A 正文 254（上轮的短 probe）', 0xE13A, b'\x00' * 254),
        ('0xE13A 正文 817 全零（对照）', 0xE13A, b'\x00' * 817),
        ('0x5290 占位 2431（表阶段）', 0x5290, b'\x00' * 2431),
    ]

    ok = True
    for name, op, body in cases:
        hx = fa.op_block(op, body)
        data = bytes.fromhex(hx)
        frames, consumed = decode_stream(data)
        real = [f for f in frames if f[3] is not None]
        first = real[0]
        pad = real[1:]
        pad_bytes = sum(f[0] for f in pad)
        leftover = len(data) - consumed
        want_payload = len(body) + 2
        good = (
            first[3] == want_payload
            and first[4][:2] == op.to_bytes(2, 'little')
            and first[4][2:] == body
            and leftover == 0
            and all(f[4][:2] == b'\xff\xff' for f in pad)
        )
        ok = ok and good
        print(f'{"PASS" if good else "FAIL"}  {name}')
        print(f'      发 {len(data):6d}B = {data[:6].hex()} ...  '
              f'首帧 total={first[0]} k={first[2]} len={first[3]} '
              f'payload={first[4][:4].hex()}…')
        if pad:
            print(f'      对齐填充：{len(pad)} 个 dummy 帧，共 {pad_bytes}B，'
                  f'opcode 全 0xFFFF = {all(f[4][:2] == bytes([0xFF, 0xFF]) for f in pad)}')
        print(f'      解码器消化 {consumed}B，剩余 {leftover}B')
    print()
    print('总结：' + ('全部通过 —— 服务端的帧封装与客户端解码器逐字节吻合'
                     if ok else '有不通过项，见上'))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
