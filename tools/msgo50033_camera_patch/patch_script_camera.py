# -*- coding: utf-8 -*-
"""机库相机注视点修复（客户端脚本容器等长改写）。

背景：
    机库「武器改造 / 强化」界面的相机脚本用 chara.getHeight() 现算注视点：

        local height = chara.getHeight();
        height *= 0.55;          <- 本环境该函数返回约 0，0 乘任何数还是 0
        target.y += height;      <- 注视点停在脚底，镜头又陡又矮

    视角正常的「装备组」脚本用绝对注视点 Vec(650, 83, -92)，固定胸部高度。
    所以把乘算换成绝对值（height = 63.30; => target.y 约 19.7+63.3 = 83）即可对齐。

为什么必须等长：
    FPMF 归档没有空洞 / 重定位机制，data/script/0000.dat 里每条记录的
    offset / size 都写死在 script.hed 里，改长度会让后续所有记录整体错位。
    `height *= 0.5;`  (14 字符) -> `height = 63.3;`  (14 字符)
    `height *= 0.55;` (15 字符) -> `height = 63.30;` (15 字符)
    替换前后字符数与字节数都相等，因此不需要改 script.hed 的 size / resource_key
    （resource_key 只依赖明文首字节与总长度，两者都没变）。

    ★ .nut 是 UTF-16LE 带 BOM，14 字符 = 28 字节、15 字符 = 30 字节；
      按「字符数」判断会算错，本脚本一律按字节校验。

用法（游戏根目录 = 含 GundamOnline_CHINA.exe 的目录）：
    # 干跑：只打印将要改什么，不写任何字节
    python patch_script_camera.py --game "<游戏根目录>" --fpmf-dir "<含 fpmf.py 的目录>"

    # 备份 + 改写 + 逐条双向回读校验
    python patch_script_camera.py --game "<游戏根目录>" --fpmf-dir "<...>" --apply

    # 调高 / 调低注视点，或从最近一次备份还原
    python patch_script_camera.py --game "<游戏根目录>" --fpmf-dir "<...>" --apply --height 75.3
    python patch_script_camera.py --game "<游戏根目录>" --restore

依赖：
    fpmf.py（FPMF 归档读写模块：load_keys / parse_hed / read_resource /
    write_resource_inplace / calculate_resource_key）。按以下顺序查找：
    --fpmf-dir 指定目录 -> 本脚本同目录 -> 已在 PYTHONPATH 中。
    密钥表默认从游戏目录下的 GundamOnline_CHINA.exe 里按签名提取；
    也可用 --key-bin 指定离线的两张 0x800 表。

    配套的零依赖单文件补丁 修复机库相机.cmd 不需要 fpmf.py，
    直接放游戏根目录双击即可（详见 README.md）。

改完必须**完整重启客户端**（脚本在启动时读入内存，只重登无效）。
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

# 已验证的 7 个脚本；L03_CharaSelect_Camera_01.nut（装备组）本来就是对的，别动。
TARGETS = [
    "L03_WeaponWindow_Camera_01.nut",
    "L03_WeaponWindow_Camera_03.nut",
    "L03_HangarMenu_Camera_01.nut",
    "L03_HangarMenu_04.nut",
    "Menu_Camera_Hangar_OverCustom_03.nut",
    "Menu_Camera_Hangar_OverHaul_03.nut",
    "Menu_Camera_Hangar_BuildupMsma_03.nut",
]

# 原串 -> 等长替换模板。数字宽度要分别对齐，否则拒绝改。
PATTERNS = {
    "height *= 0.5;": "height = {};",
    "height *= 0.55;": "height = {};",
}
NUM_WIDTH = {"height *= 0.5;": 4, "height *= 0.55;": 5}   # 63.3 / 63.30


def format_height(orig: str, height: float) -> str:
    """按原串长度拼出等长的新串。"""
    width = NUM_WIDTH[orig]
    body = ("%.2f" % height)[:width].rstrip(".")
    if body.endswith("."):
        body += "0"
    text = PATTERNS[orig].format(body)
    if len(text) != len(orig):
        raise ValueError("替换后长度不等：%r(%d) -> %r(%d)"
                         % (orig, len(orig), text, len(text)))
    return text


def load_fpmf(fpmf_dir: str | None):
    if fpmf_dir:
        sys.path.insert(0, str(Path(fpmf_dir).resolve()))
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    try:
        import fpmf
    except ImportError as e:
        raise SystemExit("缺少 fpmf.py：放到本脚本同目录、或用 --fpmf-dir 指定、"
                         "或加入 PYTHONPATH。%s" % e)
    return fpmf


def resolve_game(arg: str | None) -> Path:
    """优先用 --game；未给则从 cwd / 脚本目录向上找 GundamOnline_CHINA.exe。"""
    cands = []
    if arg:
        cands.append(Path(arg).resolve())
    else:
        cands += [Path.cwd(), HERE, HERE.parent, HERE.parent.parent]
    for p in cands:
        if (p / "GundamOnline_CHINA.exe").is_file():
            return p
    raise SystemExit("找不到游戏根目录（需要含 GundamOnline_CHINA.exe）。"
                     "请用 --game 指定，例如 --game \"D:/MSOL/GundamOnline\"。")


def newest_backup(root: Path) -> Path | None:
    if not root.is_dir():
        return None
    dirs = sorted((d for d in root.iterdir() if d.is_dir()
                   and d.name.startswith("camera_")), reverse=True)
    return dirs[0] if dirs else None


def do_restore(game: Path, backup_root: Path) -> int:
    src = newest_backup(backup_root)
    if src is None:
        print("没有找到相机补丁的备份目录（%s/camera_*）" % backup_root)
        return 2
    dat = src / "0000.dat"
    if not dat.is_file():
        print("备份里没有 0000.dat：%s" % dat)
        return 2
    dst = game / "data" / "script" / "0000.dat"
    shutil.copy2(dat, dst)
    print("已还原：%s -> %s" % (dat, dst))
    meta = src / "meta.json"
    if meta.is_file():
        info = json.loads(meta.read_text(encoding="utf-8"))
        print("备份时间 %s，当时改了 %d 个脚本，height=%s"
              % (info.get("time"), len(info.get("records", [])), info.get("height")))
    print("记得完整重启客户端。")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="机库相机注视点等长修复")
    ap.add_argument("--game", default=None,
                    help="游戏根目录（含 GundamOnline_CHINA.exe）；省略则自动向上查找")
    ap.add_argument("--fpmf-dir", default=None, help="含 fpmf.py 的目录")
    ap.add_argument("--key-bin", default=None, help="备用 FPMF 密钥表（.bin）")
    ap.add_argument("--backup-root", default=str(Path.cwd() / "_msgo_camera_backup"),
                    help="备份目录根，默认 ./_msgo_camera_backup")
    ap.add_argument("--height", type=float, default=63.3,
                    help="注视点高度（目标 y = 站立 y 19.7 + 该值；63.3 => y=83，"
                         "与装备组一致；可试 75.3）")
    ap.add_argument("--apply", action="store_true", help="真正写入（默认只干跑）")
    ap.add_argument("--restore", action="store_true", help="从最近备份还原")
    args = ap.parse_args(argv)

    game = resolve_game(args.game)
    backup_root = Path(args.backup_root).resolve()

    if args.restore:
        return do_restore(game, backup_root)

    fpmf = load_fpmf(args.fpmf_dir)
    key_cands = [game / "GundamOnline_CHINA.exe"]
    if args.key_bin:
        key_cands.insert(0, Path(args.key_bin))
    keys = fpmf.load_keys(*key_cands)
    print("游戏目录：%s" % game)
    print("密钥来源：%s" % keys.source)

    hed = game / "data" / "script.hed"
    if not hed.is_file():
        raise SystemExit("找不到 %s" % hed)
    archive = fpmf.parse_hed(hed, keys, data_root=game / "data")
    print("script.hed 记录数 %d，DAT 模板 %r"
          % (len(archive.records), archive.dat_template))

    plans = []
    for name in TARGETS:
        hits = [r for r in archive.records
                if r.logical_path.replace("\\", "/").endswith("/" + name)
                or r.file_name == name]
        if not hits:
            print("!! %-42s 索引里找不到" % name)
            continue
        if len(hits) > 1:
            print("!! %-42s 命中 %d 条，取第一条" % (name, len(hits)))
        rec = hits[0]
        plain = fpmf.read_resource(archive, rec, keys)
        text = plain.decode("utf-16", errors="surrogatepass")
        hit = next((o for o in PATTERNS if o in text), None)
        if hit is None:
            print("   %-42s 没有 height 乘算（可能已经改过或版本不同），跳过" % name)
            continue
        new = format_height(hit, args.height)
        old_b = hit.encode("utf-16-le")
        new_b = new.encode("utf-16-le")
        if len(old_b) != len(new_b):
            print("!! %-42s 字节长度不等 %d != %d，拒绝" % (name, len(old_b), len(new_b)))
            continue
        idx = plain.find(old_b)
        if idx < 0 or plain.find(old_b, idx + 1) >= 0:
            print("!! %-42s 明文里命中 %d 次，拒绝（要唯一）"
                  % (name, plain.count(old_b)))
            continue
        patched = bytearray(plain)
        patched[idx:idx + len(old_b)] = new_b
        key_same = (fpmf.calculate_resource_key(bytes(patched))
                    == fpmf.calculate_resource_key(plain))
        plans.append(dict(record=rec, name=name, orig=hit, new=new,
                          offset=idx, plain=bytes(plain), patched=bytes(patched),
                          key_same=key_same))

    if not plans:
        print("没有需要改的脚本（全部已改过，或客户端版本不同）。")
        return 0

    print("\n计划改写 %d 个脚本（height=%s）：" % (len(plans), args.height))
    for p in plans:
        print("  %-42s %-18r -> %-18r  明文偏移 %d，资源键不变 %s"
              % (p["name"], p["orig"], p["new"], p["offset"], p["key_same"]))

    if not args.apply:
        print("\n（干跑，未写入。加 --apply 执行）")
        return 0

    dat = game / "data" / "script" / "0000.dat"
    stamp = time.strftime("%Y%m%d_%H%M%S")
    backup_dir = backup_root / ("camera_%s" % stamp)
    backup_dir.mkdir(parents=True, exist_ok=True)
    print("\n备份 %s（%.1f MB）..." % (dat, dat.stat().st_size / 1048576))
    shutil.copy2(dat, backup_dir / "0000.dat")

    meta = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "height": args.height,
        "game": str(game),
        "keys": keys.source,
        "records": [{"name": p["name"], "logical": p["record"].logical_path,
                     "dat_index": p["record"].dat_index, "offset": p["record"].offset,
                     "size": p["record"].size,
                     "resource_key": "%016X" % p["record"].resource_key,
                     "orig": p["orig"], "new": p["new"]} for p in plans],
    }
    (backup_dir / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print("备份完成：%s" % backup_dir)

    for p in plans:
        fpmf.write_resource_inplace(archive, p["record"], keys, p["patched"])
        back = fpmf.read_resource(archive, p["record"], keys)
        ok = back == p["patched"]
        same_len = len(back) == p["record"].size
        print("  %-42s 写入 %s，双向回读 %s，长度 %d%s"
              % (p["name"], "OK" if ok else "失败", "一致" if ok else "不一致",
                 len(back), "" if same_len else " ★长度变了"))
        if not ok:
            print("!! 回读不一致，请用 --restore 还原")
            return 3

    print("\n全部完成。**完整重启客户端**后进武器改造界面看效果。")
    print("若不满意：改 --height 重新 --apply，或 --restore 还原。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
