# -*- coding: utf-8 -*-
"""自检：同进程内起监听线程 -> 自己发 ODS -> 看能否收到（不写任何文件）。"""
import ctypes, sys, threading, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import ods_listen as O

t = threading.Thread(target=O.main, args=(["--seconds", "5"],), daemon=True)
t.start()
time.sleep(1.5)
for i in range(3):
    ctypes.windll.kernel32.OutputDebugStringA(f"ODS_SELFTEST_hello_{i}".encode())
    time.sleep(0.25)
t.join(timeout=12)
print("RESULT:", "PASS 已捕获" if t.is_alive() is False else "未退出")
