#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""确保 hosts 里有 gundam-reburn 需要的两条映射（需要管理员权限）。

为什么要它：
    客户端点「登录」时会先发一个 HTTP 请求
        http://ms.patch1.9you.com/launcher/authsv.csv?t=<随机>
    实测**失败阶段不同，客户端表现完全不同**：
      - 能解析域名、但 TCP 连不上（hosts → 127.0.0.1:80 无人监听）
            → 登录面板「当前战区」= 内置兜底「技术测试区」（可用，能进下一步）
      - 连域名都解析不了（hosts 里没有记录，DNS 报 NXDOMAIN）
            → 「当前战区」= `---`，点「选择战区」列表空白，点「登录」弹「请选择战区」
    2026-10-14 20:05 实测这两条记录被抹掉后，客户端就退化成第二种、卡在登录界面。

本脚本幂等：已经有就跳过，没有才追加。
"""
from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

HOSTS = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
WANTED = [
    ("127.0.0.1", "ms.patch1.9you.com"),
    ("127.0.0.1", "ms.9you.com"),
]
MARK = "# gundam-reburn"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def main() -> int:
    print(f"[*] hosts = {HOSTS}")
    print(f"[*] admin = {is_admin()}")
    try:
        text = HOSTS.read_text(encoding="utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        print(f"[X] 读不到 hosts: {e}")
        return 2

    low = text.lower()
    add: list[str] = []
    for ip, host in WANTED:
        if host.lower() in low:
            print(f"[=] 已有 {host}，跳过")
            continue
        add.append(f"{ip} {host}")
    if not add:
        print("[*] hosts 已满足要求，无需修改")
        return 0

    tail = "" if text.endswith("\n") else "\n"
    block = ""
    if MARK.lower() not in low:
        block += f"{MARK}\n"
    block += "".join(f"{ln}\n" for ln in add)
    try:
        with HOSTS.open("a", encoding="utf-8") as fh:
            fh.write(tail + block)
    except Exception as e:  # noqa: BLE001
        print(f"[X] 写 hosts 失败（一般是没有管理员权限）: {e}")
        return 3

    print("[*] 已追加:")
    for ln in add:
        print(f"      {ln}")
    # 复核
    try:
        import socket
        ip = socket.gethostbyname("ms.patch1.9you.com")
        print(f"[*] 复核解析 ms.patch1.9you.com -> {ip}")
    except Exception as e:  # noqa: BLE001
        print(f"[!] 复核解析失败: {e}")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    raise SystemExit(main())
