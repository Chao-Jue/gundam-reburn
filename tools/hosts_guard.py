#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""hosts 守护：每 5 秒检查一次，缺 `127.0.0.1 ms.patch1.9you.com` 就补回去。

为什么需要它
------------
实测 hosts 里那两条映射会被**外部程序定时抹掉**（16:06:31、16:35:00 两次，
间隔约 28 分钟；tools/ 里没有任何代码删它，系统里有 Defender 在跑）。
而客户端只在**启动后约 28 秒**拉一次战区清单：
    http://ms.patch1.9you.com/launcher/authsv.csv
hosts 没了的后果不是"连不上"，而是**列表退化成内置的两个无 IP 条目**
（「第一战区（XXX）」「第二战区（服务器）」），点登录在本地就失败、连连接都不发。

本脚本 **必须用管理员权限运行**（写 hosts 需要），一般由 tools/start_local.cmd
以 `start /b` 方式拉起。

用法：
    python tools/hosts_guard.py             # 常驻，5 秒一轮
    python tools/hosts_guard.py --once      # 只补一次就退
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

HOSTS = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
WANTED = [
    ("127.0.0.1", "ms.patch1.9you.com"),
    ("127.0.0.1", "ms.9you.com"),
]


def missing() -> list[tuple[str, str]]:
    try:
        txt = HOSTS.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    low = txt.lower()
    return [(ip, host) for ip, host in WANTED if host.lower() not in low]


def patch() -> bool:
    add = missing()
    if not add:
        return False
    try:
        with HOSTS.open("a", encoding="utf-8") as fh:
            for ip, host in add:
                fh.write(f"\n{ip} {host}\n")
        print("%s  restored: %s" % (time.strftime("%H:%M:%S"), add), flush=True)
        return True
    except Exception as e:  # noqa: BLE001
        print("%s  patch failed (need admin?): %r" % (time.strftime("%H:%M:%S"), e),
              flush=True)
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()

    if a.once:
        print("missing:", missing())
        patch()
        return 0

    print("hosts guard started, target = %s" % HOSTS, flush=True)
    patch()
    while True:
        time.sleep(a.interval)
        patch()


if __name__ == "__main__":
    sys.exit(main())
