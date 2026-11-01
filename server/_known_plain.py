"""已知明文攻击：用解密后的 settings 原文去撞 data/settings/0000.dat 容器。

思路：
  1. 取出解密文件里几段高区分度的字符串（中文名、IP、英文关键字）；
  2. 在容器里按  utf-8 / gbk / shift-jis / utf-16le  以及 "先异或单字节 0..255" 的变换搜索；
  3. 命中即证明容器是"明文 + 可选单字节异或"，能直接反推容器格式。
不修改任何文件，只读。
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(r"D:\project\gundam-reburn")
DEC = ROOT / "GundamOnline_CHINA_已解密" / "decrypted" / "settings"
CLI = ROOT / "launcher" / "gundam" / "机动战士敢达Online" / "GundamOnline"

TARGETS = {
    "authsv.csv": ["技术测试区", "60.206.12.127", "認証サーバーリスト", "第二"],
    "autoexec.cfg": ["wnd_width", "camera_world_far_z", "camera_lockon_range"],
    "error_code.csv": ["登陆失败", "认证系统错误", "Token"],
    "config.cfg": ["character_move_speed", "device_multisamples"],
    "sv_add.txt": ["125.211.208.155", "審査版"],
    "world_map.csv": None,       # 只取文件头
    "str_table.txt": ["战斗", "机体"],
}

ENCS = ("utf-8", "gbk", "shift_jis", "utf-16le")


def read_head(p: pathlib.Path, n: int = 120) -> bytes:
    with p.open("rb") as f:
        return f.read(n)


def xor(data: bytes, k: int) -> bytes:
    if k == 0:
        return data
    return bytes(b ^ k for b in data)


def main() -> int:
    blob_path = CLI / "data" / "settings" / "0000.dat"
    hed_path = CLI / "data" / "settings.hed"
    blob = blob_path.read_bytes()
    print(f"[容器] {blob_path.name} = {len(blob):,} B")
    print(f"[索引] {hed_path.name} = {hed_path.stat().st_size:,} B")
    print(f"[容器头部] {blob[:64].hex(' ')}")
    print(f"[索引头部] {read_head(hed_path, 64).hex(' ')}")
    print()

    needles: list[tuple[str, bytes, str]] = []
    for fname, kws in TARGETS.items():
        p = DEC / fname
        if not p.exists():
            continue
        if kws is None:
            needles.append((fname + ":头", read_head(p), "raw"))
            continue
        raw = p.read_bytes()
        for kw in kws:
            for enc in ENCS:
                try:
                    nb = kw.encode(enc)
                except Exception:
                    continue
                if nb in raw:
                    needles.append((f"{fname}:{kw}", nb, enc))

    print(f"[探针] 共 {len(needles)} 个高区分度串")
    hits = 0
    for label, nb, enc in needles:
        if len(nb) < 4:
            continue
        for k in range(256):
            pat = xor(nb, k)
            off = blob.find(pat)
            if off >= 0:
                hits += 1
                print(f"  ★ 命中 {label!r} ({enc}) xor=0x{k:02x} @ 0x{off:x}")
                break
    if hits == 0:
        print("  × 全部未命中（容器不是明文，也不是单字节异或）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
