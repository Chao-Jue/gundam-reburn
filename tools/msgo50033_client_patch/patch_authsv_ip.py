# -*- coding: utf-8 -*-
"""等长改写 50033 客户端的认证服务器 IP / 端口（FPMF settings.hed + 0000.dat）。

为什么必须「等长」：
    data/settings/0000.dat 是一整包顺序排列的资源，settings.hed 里每条记录只存
    (offset, size, resource_key)。改动任何一条记录的字节长度都会让后续所有记录
    的 offset 整体错位，客户端读到乱码甚至启动失败；FPMF 也没有空洞/重定位机制。
    因此这里只替换数据行里的 IP/端口字段，长短差从「第一个数据行的组名尾部空格」
    里扣掉或补回，保证改写后总长度与原文件逐字节相等，再原地覆盖 + 更新资源键。

    实测 127.0.0.1(9 字符) <-> 更长的 IPv4 地址（如 192.168.100.92）双向都成立；
    resource_key 只依赖明文首字节与长度，必须同步用 calculate_resource_key() 重算，
    否则 HED 校验失败、客户端直接忽略该资源。

用法：
    # 查看当前 authsv.csv / authsv_stg.csv 的数据行与资源键状态
    python patch_authsv_ip.py status --client-root "<游戏安装目录>"

    # 改成本机自建服务端（会先把两个原文件备份到 data/_msgo_ipbackup_<时间戳>/）
    python patch_authsv_ip.py patch --client-root "<游戏安装目录>" \
        --host 127.0.0.1 --port 30000

    # 换成别的部署地址（局域网 / 内网穿透等）
    python patch_authsv_ip.py patch --client-root "<游戏安装目录>" \
        --host 192.168.100.92 --port 30000

依赖：
    fpmf.py（FPMF 归档读写模块：load_keys / parse_hed / read_resource /
    write_resource_inplace / repoint_record / write_hed / calculate_resource_key）。
    放在本脚本同目录、或由 --fpmf-dir 指定、或已在 PYTHONPATH 中。
    密钥表由 fpmf.load_keys() 从游戏目录下的 GundamOnline_CHINA.exe 读取。

提醒：改完客户端这两个文件后，服务端认证清单 fake_root/launcher/authsv.csv
    的 zone_host 必须同步改成同一个地址（本仓库在 server/fake_root/ 下，
    50033 自建服务端在 dataset/fake_root/ 下）；只改一侧会连不上且没有任何报错提示。
"""
from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path

VARIANTS = ("authsv.csv", "authsv_stg.csv")


def rows(text: str):
    for raw in text.split("\n"):
        line = raw[:-1] if raw.endswith("\r") else raw
        s = line.strip()
        yield (s and not s.startswith("#")), line


def rewrite_equal_length(text: str, host: str, port: int) -> str | None:
    """返回与原文本等长的新文本；做不到（组名剩余空格不够）返回 None。"""
    nl = "\r\n" if "\r\n" in text else "\n"
    lines, n_ip = [], 0
    for is_data, line in rows(text):
        if is_data:
            f = line.split(",")
            if len(f) >= 3 and f[2].strip():
                f[2] = host
                if len(f) >= 4:
                    f[3] = str(port)
                line = ",".join(f)
                n_ip += 1
        lines.append(line)
    if not n_ip:
        return None
    out = nl.join(lines)
    delta = len(out) - len(text)
    if delta == 0:
        return out
    for i, (is_data, _) in enumerate(rows(text)):
        if not is_data:
            continue
        f = lines[i].split(",")
        if len(f) < 2:
            return None
        if delta > 0:                      # 变长 → 扣组名尾部空格
            spaces = len(f[1]) - len(f[1].rstrip(" "))
            if spaces < delta:
                return None
            f[1] = f[1][: len(f[1]) - delta]
        else:                              # 变短 → 组名补空格
            f[1] = f[1] + " " * (-delta)
        lines[i] = ",".join(f)
        break
    out = nl.join(lines)
    return out if len(out) == len(text) else None


def load(client_root: Path, fpmf_dir: Path | None):
    if fpmf_dir:
        sys.path.insert(0, str(fpmf_dir))
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import fpmf
    except ImportError as e:
        raise SystemExit("缺少 fpmf.py：放到本脚本同目录或用 --fpmf-dir 指定。%s" % e)
    exe = client_root / "GundamOnline_CHINA.exe"
    hed = client_root / "data" / "settings.hed"
    if not exe.is_file() or not hed.is_file():
        raise SystemExit("client-root 里找不到 GundamOnline_CHINA.exe 或 data/settings.hed：%s"
                         % client_root)
    keys = fpmf.load_keys(exe)
    ar = fpmf.parse_hed(hed, keys, data_root=client_root / "data")
    return fpmf, keys, ar


def do_status(client_root: Path, fpmf_dir: Path | None) -> int:
    fpmf, keys, ar = load(client_root, fpmf_dir)
    bad = 0
    for rec in ar.records:
        if not any(rec.logical_path.endswith(v) for v in VARIANTS):
            continue
        raw = fpmf.read_resource(ar, rec, keys)
        ok = fpmf.calculate_resource_key(raw) == rec.resource_key
        print("[%s] %dB key=%s" % (rec.logical_path, rec.size, "OK" if ok else "BAD"))
        bad += 0 if ok else 1
        for is_data, line in rows(raw.decode("utf-8", errors="replace")):
            if is_data:
                print("   ", line)
    return 1 if bad else 0


def do_patch(client_root: Path, host: str, port: int, fpmf_dir: Path | None) -> int:
    fpmf, keys, ar = load(client_root, fpmf_dir)
    targets = [r for r in ar.records
               if any(r.logical_path.endswith(v) for v in VARIANTS)]
    if not targets:
        print("没有 authsv 记录，未作任何改动")
        return 1

    # 等长可行性先全部试算，避免改到一半
    plan = []
    for rec in targets:
        old = fpmf.read_resource(ar, rec, keys)
        new_text = rewrite_equal_length(old.decode("utf-8"), host, port)
        if new_text is None:
            print("[%s] 无法等长改写，放弃（未动任何文件）" % rec.logical_path)
            return 1
        new_b = new_text.encode("utf-8")
        if len(new_b) != len(old):
            print("[%s] 长度不等，放弃（未动任何文件）" % rec.logical_path)
            return 1
        plan.append((rec, new_b))

    bk = (client_root / "data" /
          ("_msgo_ipbackup_" + time.strftime("%Y%m%d_%H%M%S")))
    bk.mkdir(parents=True, exist_ok=False)
    shutil.copy2(client_root / "data" / "settings.hed", bk / "settings.hed")
    shutil.copy2(client_root / "data" / "settings" / "0000.dat", bk / "0000.dat")
    print("备份:", bk)

    for rec, new_b in plan:
        fpmf.write_resource_inplace(ar, rec, keys, new_b)
        fpmf.repoint_record(ar, rec, offset=rec.offset, size=rec.size,
                            resource_key=fpmf.calculate_resource_key(new_b))
        print("[%s] 等长原地改写 %dB" % (Path(rec.logical_path).name, rec.size))
    fpmf.write_hed(ar, keys)

    print("=== 复核 ===")
    return do_status(client_root, fpmf_dir)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["status", "patch"])
    ap.add_argument("--client-root", required=True,
                    help="游戏安装目录（含 GundamOnline_CHINA.exe 与 data/）")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=30000)
    ap.add_argument("--fpmf-dir", default=None, help="含 fpmf.py 的目录")
    a = ap.parse_args()
    root = Path(a.client_root)
    fd = Path(a.fpmf_dir) if a.fpmf_dir else None
    if a.action == "status":
        return do_status(root, fd)
    return do_patch(root, a.host, a.port, fd)


if __name__ == "__main__":
    raise SystemExit(main())
