#!/usr/bin/env python
"""把 server/hook_runs/rtti_scan.json 里的 RTTI 侦察结果排版出来。

用法:
  python tools/show_rtti.py                 # 看默认路径
  python tools/show_rtti.py <path.json>     # 指定文件
  python tools/show_rtti.py --kw World      # 只看名字含关键字的类
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT = ROOT / "server" / "hook_runs" / "rtti_scan.json"


def main(argv: list[str]) -> int:
    path = DEFAULT
    kw = None
    for i, a in enumerate(argv):
        if a == "--kw" and i + 1 < len(argv):
            kw = argv[i + 1].lower()
        elif not a.startswith("-"):
            path = Path(a)
    if not path.exists():
        print(f"[!] 没有找到 {path}（先跑 tools/run_hooked.py --scan-rtti N）")
        return 1

    p = json.loads(path.read_text(encoding="utf-8"))
    st = p.get("selftest") or {}
    print(f"标签 {p.get('tag')}  类 {p.get('nClass')}  虚表 {p.get('nVtable')}  "
          f"{p.get('ranges')} 区 / {(p.get('bytes') or 0)/1048576:.1f}MB  "
          f"{p.get('ms')}ms  errs={p.get('errs')}")
    print(f"自检 {st.get('main')}  Themida x{st.get('themida')}  .?AV x{st.get('av')}")

    vt = p.get("vt") or []
    if vt:
        print("\n== vtable 解析 ==")
        for v in vt:
            if kw and kw not in v["name"].lower():
                continue
            print(f"  {v['name']}")
            print(f"    desc={v['desc']}  vtable={v['vtable']}")
            print(f"    槽: {', '.join(v.get('slots') or [])}")

    for v in (p.get("insts") or []):
        if kw and kw not in v["name"].lower():
            continue
        print(f"\n== {v['name']}  vt={v['vt']}")
        if v.get("code"):
            print(f"  构造锚点(代码页命中): {', '.join(v['code'])}")
        if not v.get("n"):
            print("  live 实例: 0（此刻还没构造）")
            continue
        for it in v["insts"]:
            print(f"  实例 @{it['at']}")
            ws = it.get("w") or []
            for i in range(0, len(ws), 6):
                print("     +0x%02x  %s" % (i * 4, "  ".join(ws[i:i + 6])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
