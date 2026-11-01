"""Run an existing client wire reader offline, without touching a live process.

Requires unicorn. Reports consumed bytes and input-to-struct byte offsets.
"""
import argparse
import json
from pathlib import Path
import struct

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EAX

ROOT = Path(__file__).resolve().parents[1]


def decode(address, data, output_size=0x1000):
    image = (ROOT / 'server/img_dump/main_GundamOnline_CHINA.exe').read_bytes()
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(0x400000, (len(image) + 0xFFF) & ~0xFFF)
    uc.mem_write(0x400000, image)
    for base in (0x20000000, 0x21000000, 0x22000000, 0x23000000, 0x24000000):
        uc.mem_map(base, 0x10000)
    uc.mem_write(0x22000000, data)
    uc.mem_write(0x23000000, struct.pack('<II', 0x22000000, 0x22000000 + len(data)))
    uc.mem_write(0x20008000, struct.pack('<III', 0x24000000, 0x21000000, 0x23000000))
    uc.reg_write(UC_X86_REG_ESP, 0x20008000)
    uc.emu_start(address, 0x24000000, count=100000)
    consumed = struct.unpack('<I', uc.mem_read(0x23000000, 4))[0] - 0x22000000
    return uc.reg_read(UC_X86_REG_EAX) & 0xFF, consumed, bytes(uc.mem_read(0x21000000, output_size))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('address', type=lambda v: int(v, 0))
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    ok, consumed, _ = decode(args.address, bytes(4096))
    mapping = []
    # One-hot byte probes are unambiguous even around unaligned fields/padding.
    for offset in range(consumed):
        data = bytearray(consumed)
        data[offset] = 1
        success, count, output = decode(args.address, bytes(data))
        mapping.append({'wire': offset, 'struct': [i for i, v in enumerate(output) if v]})
        if not success or count != consumed:
            raise RuntimeError('reader is not a fixed direct-copy structure')
    result = {'address': hex(args.address), 'success': ok, 'wire_size': consumed,
              'mapping': mapping}
    output = json.dumps(result, indent=2)
    if args.out: args.out.write_text(output, encoding='utf-8')
    print('reader=%#x success=%d wire_size=%d' % (args.address, ok, consumed))


if __name__ == '__main__':
    main()
