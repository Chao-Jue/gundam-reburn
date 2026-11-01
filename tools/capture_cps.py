"""轮询截获保护模块的内核驱动（CPS.sys 之类）。

保护模块在初始化时会把它加密内嵌的 x64 驱动写到
%windir%\\SysWOW64\\CPS.sys，然后 CreateService + StartService，
失败后立刻把服务键和文件都删掉。所以必须在"文件存在的那几十毫秒"
里把它拷出来。

用法（先跑本脚本，再启动客户端）：

    python tools/capture_cps.py            # 监控 180 秒
    python tools/capture_cps.py -s 300     # 监控 300 秒
    python tools/capture_cps.py -i 0.001   # 1ms 轮询

产物：server/cps_dump/<名字>.<时间戳>.sys

本脚本是"保底"手段，不需要 frida；frida 版（tools/run_hooked.py）
会在 StartServiceW 入口用 CopyFileW 精确抓取，二者可同时跑。
"""

from __future__ import annotations

import argparse
import ctypes
import os
import shutil
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 32 位进程取 SystemDirectory 会被 WOW64 重定向到 SysWOW64；
# 但模块日志里写的是显式的 %windir%\SysWOW64\CPS.sys，所以两个真实目录都要盯。
WATCH_DIRS = [
    r"C:\Windows\SysWOW64",
    r"C:\Windows\SysWOW64\drivers",
    r"C:\Windows\System32\drivers",
    r"C:\Windows\System32",
]

# 名字里带这些片段的 .sys 都值得抓（CPS 是主目标）
NAME_HINTS = ("cps", "xgg", "dlib", "k_ds", "ng", "gd")


def service_image_paths() -> list[str]:
    """若保护模块此刻已经把 CPS 服务建好了，直接从注册表拿到它的真实路径。"""
    out: list[str] = []
    try:
        import winreg  # type: ignore

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"
        ) as services:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(services, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(services, name) as key:
                        path, _ = winreg.QueryValueEx(key, "ImagePath")
                        stype, _ = winreg.QueryValueEx(key, "Type")
                except OSError:
                    continue
                if not isinstance(path, str):
                    continue
                low = path.lower()
                if "cps.sys" in low or (int(stype) & 1 and not low.startswith(r"\systemroot")):
                    cleaned = path.replace(r"\??\\", "").replace(r"\??\\", "")
                    if cleaned.startswith("\\") or cleaned.startswith("?"):
                        cleaned = cleaned.lstrip("\\?")
                    out.append(cleaned)
    except Exception:
        pass
    return out


class Watcher:
    def __init__(self, out_dir: Path, interval: float) -> None:
        self.out_dir = out_dir
        self.interval = interval
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.seen: set[str] = set()
        self.got: list[Path] = []
        self.stop = threading.Event()

    # ---------- 拷贝 ----------
    def try_copy(self, src: str, why: str) -> bool:
        if src in self.seen:
            return False
        p = Path(src)
        try:
            if not p.is_file():
                return False
            size = p.stat().st_size
            if size <= 0:
                return False
        except OSError:
            return False

        self.seen.add(src)
        stamp = time.strftime("%Y%m%d_%H%M%S") + f"_{int(time.time()*1000)%1000:03d}"
        dst = self.out_dir / f"{p.name}.{stamp}.sys"

        # 文件可能正被写入，重试几次直到大小稳定
        for attempt in range(30):
            try:
                shutil.copy2(str(p), str(dst))
                a = dst.stat().st_size
                time.sleep(0.001)
                b = p.stat().st_size if p.exists() else a
                if a == b and a == size:
                    break
                size = b
            except OSError:
                if not p.exists():
                    # 源文件被删了，但我们可能已经拷到一部分
                    break
                time.sleep(0.002)

        if dst.exists() and dst.stat().st_size > 0:
            print(f"[+] 抓到驱动  {src}")
            print(f"    ({why}) -> {dst}  ({dst.stat().st_size} 字节)")
            self.got.append(dst)
            return True
        return False

    # ---------- 主循环 ----------
    def run(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        dirs = [Path(d) for d in WATCH_DIRS if Path(d).is_dir()]
        known: dict[str, set[str]] = {
            str(d): {e.name.lower() for e in d.iterdir()} if d.is_dir() else set()
            for d in dirs
        }
        print(f"[*] 监控 {len(dirs)} 个目录，轮询 {self.interval*1000:.1f}ms，"
              f"共 {seconds:.0f} 秒。现在去启动客户端。")
        for d in dirs:
            print(f"    {d}")
        print("[*] 等待 CPS.sys 出现……")

        while not self.stop.is_set() and time.monotonic() < deadline:
            # 1) 服务注册表里已知的路径（最精确）
            for path in service_image_paths():
                if path.lower().endswith(".sys"):
                    self.try_copy(path, "registry ImagePath")

            # 2) 目录里新出现的 .sys
            for d in dirs:
                try:
                    now = {e.name.lower(): e for e in d.iterdir()}
                except OSError:
                    continue
                for name, ent in now.items():
                    if not name.endswith(".sys"):
                        continue
                    if name in known.get(str(d), set()):
                        continue
                    if any(h in name for h in NAME_HINTS) or "cps" in name:
                        self.try_copy(str(ent), f"new in {d}")
                known[str(d)] = set(now.keys())

            time.sleep(self.interval)

    def stop_now(self) -> None:
        self.stop.set()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-s", "--seconds", type=float, default=180.0)
    ap.add_argument("-i", "--interval", type=float, default=0.005)
    ap.add_argument("-o", "--out", default=str(ROOT / "server" / "cps_dump"))
    args = ap.parse_args()

    if os.name != "nt":
        print("此脚本只能在 Windows 上运行。", file=sys.stderr)
        return 2

    watcher = Watcher(Path(args.out), args.interval)
    try:
        watcher.run(args.seconds)
    except KeyboardInterrupt:
        watcher.stop_now()

    if watcher.got:
        print(f"\n[=] 共抓到 {len(watcher.got)} 个文件：")
        for f in watcher.got:
            print(f"    {f}")
        return 0
    print("\n[-] 监控期间没有抓到驱动文件。")
    print("    可能原因：客户端没启动 / 文件生命周期过短。" )
    print("    请改用 frida 版：python tools/run_hooked.py（在 StartServiceW 入口精确抓取）。")
    return 1


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    raise SystemExit(main())
