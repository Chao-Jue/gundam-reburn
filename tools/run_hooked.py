"""用 frida 在 Win32 API 边界上"骗过"保护模块的驱动加载检查。

流程：挂起方式启动 GundamOnline_CHINA.exe -> 注入 tools/xgg_hook.js ->
恢复运行 -> 实时打印保护模块调用的每一个 SCM/驱动 API -> 结束后汇总。

第一次试（默认）：只伪造 StartServiceW 的返回值，看日志从
`STARTSERVICEERROR` 变成什么，从而摸清还要往下伪造哪些字段。

用法：
    python tools/run_hooked.py                     # 默认只 fake StartServiceW
    python tools/run_hooked.py --fake all          # 全量伪造
    python tools/run_hooked.py --fake startService,queryStatus,deviceIo
    python tools/run_hooked.py --trace-only        # 只记录，不改任何返回值
    python tools/run_hooked.py --seconds 60        # 观察 60 秒

前置：pip install frida（隔离环境见 note）。需要管理员权限（SCM 操作）。
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JS_PATH = Path(__file__).resolve().with_name("xgg_hook.js")
LOG_PATH = ROOT / "server" / "hook_log.txt"

sys.path.insert(0, str(Path(__file__).resolve().parent))  # 便于 import clean_cps
try:
    import clean_cps  # noqa: E402
except Exception:  # pragma: no cover
    clean_cps = None  # type: ignore

DEFAULT_ARG = "./data/"

# 最小必要 hook 集（默认）。
# Themida 启动时会扫描一批系统 API 的入口字节，被 frida 打了内联跳板就判定为
# "虚拟机"并自杀（详见 xgg_hook.js 里的说明和实测数据）。所以默认只装伪造驱动链
# 真正需要的这几个；要排查别的问题时用 --full 全开（代价是可能触发 Themida）。
MINIMAL_HOOKS = [
    "advapi32.dll!OpenSCManagerW",
    "advapi32.dll!OpenServiceW",
    "advapi32.dll!CreateServiceW",
    "advapi32.dll!StartServiceW",
    "advapi32.dll!QueryServiceStatus",
    "advapi32.dll!QueryServiceStatusEx",
    "advapi32.dll!ControlService",
    "advapi32.dll!DeleteService",
    "advapi32.dll!CloseServiceHandle",
    "kernel32.dll!CreateFileW",
    "kernel32.dll!DeviceIoControl",
    "kernel32.dll!LoadLibraryW",
    "kernel32.dll!LoadLibraryA",
    "kernel32.dll!LoadLibraryExW",
    "kernel32.dll!GetProcAddress",
    "kernel32.dll!CreateThread",
    # 只观察、不改行为：崩溃时把异常记录/寄存器完整打出来（排查 0xC0000005 用）
    "kernel32.dll!UnhandledExceptionFilter",
    "kernel32.dll!SetUnhandledExceptionFilter",
]

CANDIDATE_PATHS = [
    r"C:\Windows\SysWOW64\CPS.sys",
    r"C:\Windows\System32\drivers\CPS.sys",
    r"C:\Windows\SysWOW64\drivers\CPS.sys",
    r"C:\Windows\System32\CPS.sys",
]

FAKE_KEYS = {
    "openScm": "openScm",            # OpenSCManagerW —— 非管理员下必须伪造
    "createService": "createService",
    "openService": "openService",
    "startService": "startService",
    "queryStatus": "queryStatus",
    "controlService": "controlService",
    "deleteService": "deleteService",
    "openDevice": "openDevice",
    "deviceIo": "deviceIo",
    "shell": "shell",
}


# ---------------------------------------------------------------- helpers
def find_exe() -> Path:
    found = [
        p
        for p in (ROOT / "launcher").rglob("GundamOnline_CHINA.exe")
        if p.parent.name == "GundamOnline"
    ]
    if not found:
        raise SystemExit("找不到 GundamOnline_CHINA.exe")
    return found[0]


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_elevated_and_wait(argv: list[str]) -> int:
    """用 runas 起一个新实例并等它结束，返回退出码。"""
    class _SEI(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_ulong), ("fMask", ctypes.c_ulong),
            ("hwnd", ctypes.c_void_p),
            ("lpVerb", ctypes.c_wchar_p), ("lpFile", ctypes.c_wchar_p),
            ("lpParameters", ctypes.c_wchar_p), ("lpDirectory", ctypes.c_wchar_p),
            ("nShow", ctypes.c_int), ("hInstApp", ctypes.c_void_p),
            ("lpIDList", ctypes.c_void_p), ("lpClass", ctypes.c_wchar_p),
            ("hkeyClass", ctypes.c_void_p), ("dwHotKey", ctypes.c_ulong),
            ("hIcon", ctypes.c_void_p), ("hProcess", ctypes.c_void_p),
        ]

    sei = _SEI()
    sei.cbSize = ctypes.sizeof(_SEI)
    sei.fMask = 0x00000040 | 0x00000100          # NOCLOSEPROCESS | NOASYNC
    sei.lpVerb = "runas"
    sei.lpFile = sys.executable
    sei.lpParameters = subprocess.list2cmdline(argv)
    sei.lpDirectory = str(ROOT)
    sei.nShow = 0                                 # 不弹控制台窗口
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        err = ctypes.get_last_error()
        print(f"[X] 提权失败（错误码 {err}"
              f"{'，你点了“否”' if err == 1223 else ''}）")
        return 3
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_void_p(sei.hProcess), 900_000)
    code = ctypes.c_ulong()
    ctypes.windll.kernel32.GetExitCodeProcess(ctypes.c_void_p(sei.hProcess),
                                              ctypes.byref(code))
    ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(sei.hProcess))
    return int(code.value)


def elevate_self() -> None:
    """不是管理员就 runas 起一个新实例（带 --out-file），等它跑完并把输出打出来。

    注意：**不能用【关机再开机】之外的方式绕过** —— 提权窗口是给当前这台机器
    上的一次 UAC 确认，点了“是”才会继续。
    """
    if os.environ.get("GUNDAM_NO_ELEVATE") == "1" or is_admin():
        return

    argv = [str(Path(sys.argv[0]).resolve())]
    argv += [a for a in sys.argv[1:] if a != "--no-elevate"]
    out_path = ROOT / "server" / "hook_runs" / "run_elevated.out"
    if "--out-file" not in argv:
        argv += ["--out-file", str(out_path)]

    print("[*] 需要管理员权限（OpenSCManagerW/CreateServiceW），正在提权重启……")
    print(f"[*] 子进程输出会写到: {out_path}")
    code = _run_elevated_and_wait(argv)
    print(f"[*] 提权子进程退出码 = {code}")
    try:
        print("[*] ---- 提权子进程输出 ----")
        print(out_path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:  # noqa: BLE001
        print(f"[!] 读不到子进程输出: {e}")
    raise SystemExit(code)


def parse_fake(spec: str | None, trace_only: bool) -> dict[str, bool]:
    fake = {k: False for k in FAKE_KEYS}
    if trace_only:
        return fake
    if spec is None:
        fake["openScm"] = True                # 非管理员时 OpenSCManagerW 返回 NULL
        fake["startService"] = True          # 默认：驱动加载链的三段
        fake["openDevice"] = True
        fake["deviceIo"] = True
        fake["shell"] = True                 # 缺 ACOPCShell.dll 时假装加载成功
        return fake
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if item == "all":
            for k in fake:
                fake[k] = True
            continue
        if item not in fake:
            raise SystemExit(f"未知的 fake 项: {item}（可选: all,{','.join(fake)}）")
        fake[item] = True
    return fake


def parse_ioctl_out(spec: str | None) -> dict:
    """--ioctl-out "0x222055=0408000000000000,0x222029=00" -> {'0x222055': '0408...'}"""
    out: dict[str, str] = {}
    for item in (spec or "").split(","):
        item = item.strip()
        if not item or "=" not in item:
            continue
        code, val = item.split("=", 1)
        code = code.strip().lower()
        if code.startswith("0x"):
            out[code] = val.strip()
        else:
            out[hex(int(code, 16)).lower()] = val.strip()
    return out


def parse_redirect(spec: str | None):
    """--redirect-connect "127.0.0.1:30000" -> ([127,0,0,1], 30000, "127.0.0.1:30000")"""
    if not spec:
        return None
    host, _, port = spec.strip().rpartition(":")
    if not host or not port.isdigit():
        return None
    try:
        octets = [int(x) for x in host.split(".")]
        if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
            return None
    except ValueError:
        return None
    return octets, int(port), spec.strip()


def build_string_patterns(words: list[str]) -> list[dict]:
    """把关键字编译成内存里可能出现的字节序列（GBK / UTF-16LE / UTF-8）。

    这个客户端是 2012~2017 年的国服，UI 文本大概率是 **GBK**（ANSI）；
    但也不能排除宽字符，所以两种都给。模式串直接交给 Frida 的
    Memory.scanSync（形如 "c7 eb d1 a1"）。
    """
    out: list[dict] = []
    for w in words:
        hexes: list[str] = []
        for enc in ("gbk", "utf-16-le", "utf-8"):
            try:
                b = w.encode(enc)
            except Exception:  # noqa: BLE001
                continue
            if len(b) < 4:
                continue
            h = " ".join(f"{x:02x}" for x in b)
            if h not in hexes:
                hexes.append(h)
        if hexes:
            out.append({"kw": w, "hex": hexes})
    return out


def build_cfg(args) -> dict:
    red = parse_redirect(getattr(args, "redirect_connect", None))
    htp = parse_redirect(getattr(args, "http_to", None))
    return {
        "dumpDir": str(Path(args.dump_dir).resolve()),
        "candidates": CANDIDATE_PATHS,
        "sysHints": ["cps", "\\\\.\\", ".sys", "xgg", "dlib", "ng"],
        "devicePatterns": ["\\\\.\\cps", "\\\\?\\cps", "\\device\\cps"],
        "deviceVersion": args.device_version,
        "fake": parse_fake(args.fake, args.trace_only),
        "fakeHandle": "0x1234",
        # SCM 与 service 必须给**不同**的假句柄：给同一个值会让客户端在
        # 两处 CloseServiceHandle 之间互相踩，且提权时本来就是"SCM 有效 / service 为 NULL"。
        "fakeScmHandle": "0x53434d31",       # 'SCM1'
        "fakeServiceHandle": "0x53455231",   # 'SER1'
        "serviceType": 1,
        "deepTrace": bool(args.deep_trace),
        "ioctlOut": parse_ioctl_out(args.ioctl_out),
        "hookWs2": bool(args.hook_ws2),
        "veh": bool(getattr(args, "veh", False)),
        "probeTable": bool(getattr(args, "probe_table", False)),
        "scanRttiAt": float(getattr(args, "scan_rtti", 0) or 0),
        "dumpImage": bool(getattr(args, "dump_image", False)),
        "scanStrings": build_string_patterns(
            [s.strip() for s in (getattr(args, "scan_str", None) or "").split(",") if s.strip()]),
        "connectTo": red[2] if red else None,
        "connectToPort": red[1] if red else 0,
        "connectToBytes": red[0] if red else None,
        # WinHTTP 劫持：把 ms.patch1.9you.com 这类请求整到本地 HTTP 服务
        "httpTo": htp[2].split(":")[0] if htp else None,
        "httpToPort": htp[1] if htp else 0,
        "skipDlls": [s.strip() for s in (args.skip_dlls or "").split(",") if s.strip()],
        "skipNames": [s.strip() for s in (args.skip_names or "").split(",") if s.strip()],
        "onlyNames": [] if args.full else MINIMAL_HOOKS,
    }


# ---------------------------------------------------------------- frida
class Logger:
    def __init__(self, path: Path, fresh: bool = True) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if fresh and self.path.exists():
            self.path.unlink()
        self.fh = self.path.open("a", encoding="utf-8")
        self.count = 0
        self.calls: list[str] = []
        self.dumps: list[str] = []
        self.rtti: list[dict] = []
        self.strs: list[dict] = []
        self.imgs: list[str] = []

    def _line(self, text: str) -> None:
        self.fh.write(text + "\n")
        self.fh.flush()

    def handle(self, message: dict, data) -> None:
        if message.get("type") == "error":
            self._line(f"[SCRIPT-ERROR] {message.get('description')}\n{message.get('stack','')}")
            print(f"[!] 脚本错误: {message.get('description')}")
            return
        if message.get("type") != "send":
            return
        p = message.get("payload", {})
        ev = p.get("ev")
        self.count += 1
        stamp = time.strftime("%H:%M:%S")

        if ev == "img":
            name = str(p.get("name") or "img").replace("\\", "_").replace("/", "_")
            dst = self.path.parent / "img_dump" / name
            try:
                dst.parent.mkdir(parents=True, exist_ok=True)
                blob = bytes(data or b"")
                dst.write_bytes(blob)
                self.imgs.append(str(dst))
                print(f"[{stamp}] >>> 镜像 dump: {name} base={p.get('base')} "
                      f"{len(blob)/1048576:.1f}MB")
            except Exception as e:  # noqa: BLE001
                print(f"[!] 镜像落盘失败 {name}: {e}")
            return
        if ev == "imgsum":
            print(f"[{stamp}] >>> 镜像 dump 完成: {p.get('n')} 段 / "
                  f"{(p.get('bytes') or 0)/1048576:.1f}MB")
            return

        if ev in ("call",) or ev in (None, "ready", "hooked", "noexport", "err"):
            self._line(f"{stamp} {json.dumps(p, ensure_ascii=False)}")
            if ev in ("ready", "noexport", "err"):
                print(f"[{stamp}] {json.dumps(p, ensure_ascii=False)}")
            return

        # API 调用/返回/伪造/dump 都值得打印
        self._line(f"{stamp} {json.dumps(p, ensure_ascii=False)}")
        if ev == "dump":
            self.dumps.append(p.get("dst", ""))
            print(f"[{stamp}] >>> 抓到驱动: {p.get('src')} -> {p.get('dst')} ({p.get('bytes')}B)")
        elif ev == "fake":
            print(f"[{stamp}] *** 伪造 {p.get('api')}: {json.dumps({k:v for k,v in p.items() if k not in ('ev','t','api')}, ensure_ascii=False)}")
        elif ev == "hooked":
            print(f"[{stamp}] hook 就绪: {p.get('dll')}::{p.get('name')}")
        elif ev == "ready":
            print(f"[{stamp}] agent ready  arch={p.get('arch')} ptr={p.get('ptrSize')} fake={p.get('fake')}")
        elif ev == "RTTI":
            # 只读侦察结果：控制台给摘要，全量落盘，别把几百个类名刷到屏上
            self.rtti.append(p)
            try:
                (self.path.parent / "rtti_scan.json").write_text(
                    json.dumps(self.rtti, ensure_ascii=False, indent=1), encoding="utf-8")
            except Exception:  # noqa: BLE001
                pass
            mb = (p.get("bytes") or 0) / 1048576.0
            st = p.get("selftest") or {}
            print(f"[{stamp}] *** RTTI 扫描[{p.get('tag')}]: "
                  f"{p.get('nClass')} 类 / {p.get('nVtable')} 虚表, "
                  f"{p.get('ranges')} 个区 / {mb:.1f}MB, 用时 {p.get('ms')}ms, errs={p.get('errs')}")
            print(f"[{stamp}]     自检({st.get('main')}): 'Themida'x{st.get('themida')} "
                  f"'.?AV'x{st.get('av')}  -> 前者>0 说明扫描器有效")
            hit = p.get("interesting") or []
            if hit:
                print(f"[{stamp}]     相关类名 {len(hit)} 个: " + ", ".join(hit[:40]))
            else:
                print(f"[{stamp}]     (没有命中关键字)")
            for v in (p.get("vt") or []):
                print(f"[{stamp}]     ★ {v.get('name')}  desc={v.get('desc')} "
                      f"vtable={v.get('vtable')} 前几槽={','.join(v.get('slots') or []) or '(空)'}")
            for v in (p.get("insts") or []):
                print(f"[{stamp}]     ◇ {v.get('name')} vt={v.get('vt')} "
                      f"代码页命中={v.get('nCode')} 数据页实例={v.get('n')}")
                if v.get("code"):
                    print(f"[{stamp}]        代码页命中(多为字节巧合，需核验): "
                          + ", ".join(v.get("code") or []))
                for it in (v.get("insts") or [])[:3]:
                    print(f"[{stamp}]        @{it.get('at')} " + " ".join(it.get("w") or []))
            (self.path.parent / "rtti_scan.json").write_text(
                json.dumps(p, ensure_ascii=False, indent=1), encoding="utf-8")
        elif ev == "WT":
            if p.get("err") or p.get("walkErr"):
                print(f"[{stamp}] !! 战区表探针失败: {p.get('err') or p.get('walkErr')}")
            else:
                print(f"[{stamp}] ★★ 战区表 CWorldMapTable: 全局={p.get('global')} "
                      f"实例={p.get('ptr')} 行数={p.get('count')} "
                      f"{p.get('note') or ''}")
                if p.get("words"):
                    print(f"[{stamp}]     前 8 dword: " + " ".join(p.get("words") or []))
                for r in (p.get("rows") or []):
                    print(f"[{stamp}]     行@{r.get('at')}: " + " ".join(r.get("w") or []))
        elif ev == "STR":
            self.strs.append(p)
            try:
                (self.path.parent / "str_scan.json").write_text(
                    json.dumps(self.strs, ensure_ascii=False, indent=1), encoding="utf-8")
            except Exception:  # noqa: BLE001
                pass
            hits = p.get("hits") or []
            mb = (p.get("bytes") or 0) / 1048576.0
            print(f"[{stamp}] *** 字符串扫描[{p.get('tag')}]: {p.get('nHit')} 处命中, "
                  f"{p.get('ranges')} 个区 / {mb:.1f}MB, 用时 {p.get('ms')}ms")
            bykw: dict[str, list[str]] = {}
            for h in hits:
                kw, _, addr = h.partition("@")
                bykw.setdefault(kw, []).append(addr)
            for kw, addrs in bykw.items():
                print(f"[{stamp}]     '{kw}' x{len(addrs)}: " + ", ".join(addrs[:6]))
            xr = p.get("xrefs") or []
            if xr:
                print(f"[{stamp}]     代码引用 {len(xr)} 条:")
                for line in xr[:12]:
                    print(f"[{stamp}]       {line}")
            else:
                print(f"[{stamp}]     (没找到直接引用 —— 可能经字符串池/间接索引访问)")
        else:
            if not ev.endswith(".ret"):
                print(f"[{stamp}] {ev}: {json.dumps(p, ensure_ascii=False)}")
            else:
                print(f"[{stamp}]   -> {ev} {json.dumps({k:v for k,v in p.items() if k not in ('ev','t')}, ensure_ascii=False)}")

    def close(self) -> None:
        self.fh.close()


args = None  # type: ignore


def query_exit_code(pid: int) -> int | None:
    """进程已退出时取退出码（仍在跑则返回 259 = STILL_ACTIVE）。"""
    k32 = ctypes.windll.kernel32
    h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return None
    try:
        code = ctypes.c_ulong()
        ok = k32.GetExitCodeProcess(h, ctypes.byref(code))
        return code.value if ok else None
    finally:
        k32.CloseHandle(h)


def collect_window_texts(pid: int) -> list[str]:
    """抓目标进程当前所有窗口/子控件的文字（弹窗文案）。"""
    user32 = ctypes.windll.user32
    found: list[str] = []

    def read_text(hwnd: int) -> str:
        buf = ctypes.create_unicode_buffer(2000)
        res = ctypes.c_size_t()
        # 用 SendMessageTimeoutW + SMTO_ABORTIFHUNG(0x2)，目标线程挂起时不会把我们卡死
        ok = user32.SendMessageTimeoutW(hwnd, 0x000D, 2000, buf, 0x0002, 80, ctypes.byref(res))
        return buf.value.strip() if ok else ""

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def on_child(hwnd, _lp):
        t = read_text(hwnd)
        if t:
            found.append(t)
        return True

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def on_top(hwnd, _lp):
        proc = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(proc))
        if proc.value != pid:
            return True
        t = read_text(hwnd)
        if t:
            found.append(t)
        user32.EnumChildWindows(hwnd, on_child, 0)
        return True

    user32.EnumWindows(on_top, 0)
    return found


def kill_existing_game() -> int:
    """结束已经在跑的客户端进程。

    本项目**同一时间只允许一个客户端**（用户明确要求），而旧客户端是提权启动的，
    普通权限杀不掉；本脚本本身就是提权运行的，所以顺手清掉。
    """
    try:
        r = subprocess.run(["taskkill", "/F", "/IM", "GundamOnline_CHINA.exe"],
                           capture_output=True, text=True, timeout=30)
    except Exception as e:  # noqa: BLE001
        print(f"[!] 清理旧客户端失败（继续）: {e}")
        return 0
    out = (r.stdout or "") + (r.stderr or "")
    n = out.count("SUCCESS") + out.count("成功")
    if n:
        print(f"[*] 已结束 {n} 个旧的客户端进程（同一时间只允许一个客户端）")
    return n


def _proc_table() -> dict:
    """pid -> (ppid, name, cmdline)。Win11 上 wmic 常没了，用 CIM。"""
    ps = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
          "Get-CimInstance Win32_Process | ForEach-Object { "
          "\"$($_.ProcessId)`t$($_.ParentProcessId)`t$($_.Name)`t$($_.CommandLine)\" }"]
    try:
        r = subprocess.run(ps, capture_output=True, text=True, timeout=90)
    except Exception as e:  # noqa: BLE001
        print(f"[!] 枚举进程失败: {e}")
        return {}
    table = {}
    for line in (r.stdout or "").splitlines():
        p = line.split("\t", 3)
        if len(p) < 4:
            continue
        try:
            pid, ppid = int(p[0].strip()), int(p[1].strip())
        except ValueError:
            continue
        table[pid] = (ppid, p[2].strip(), p[3].strip())
    return table


def kill_stale_runners() -> int:
    """结束上一轮残留的 run_hooked.py（提权进程，普通终端杀不动）。

    不清它的话，旧实例会占着 server/hook_log.txt，新一轮 0.4s 就崩。
    只杀同类 runner，**绝不碰任何祖先进程**（之前 tools/killstale.py 有过
    把提权执行器自己误杀的事故，教训记在这）。
    """
    table = _proc_table()
    if not table:
        return 0
    keep, pid = set(), os.getpid()
    while pid and pid not in keep and len(keep) < 32:
        keep.add(pid)
        pid = table.get(pid, (0, "", ""))[0]
    victims = [(p, v[2]) for p, v in table.items()
               if p not in keep and v[1].lower().startswith("python")
               and "run_hooked.py" in v[2].lower()]
    n = 0
    for p, cmd in victims:
        try:
            r = subprocess.run(["taskkill", "/F", "/PID", str(p)],
                               capture_output=True, text=True, timeout=30)
        except Exception:  # noqa: BLE001
            continue
        if r.returncode == 0:
            n += 1
            print(f"[*] 已结束残留 runner pid={p} ...{cmd[-60:]}")
    if victims and n == 0:
        print(f"[!] 有 {len(victims)} 个残留 runner 没杀掉")
    return n


def main() -> int:
    global args
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fake", default=None, help="all 或逗号列表: startService,queryStatus,deviceIo,...")
    ap.add_argument("--trace-only", action="store_true", help="只记录，不改任何返回值")
    ap.add_argument("--seconds", type=float, default=45.0, help="观察时长")
    ap.add_argument("--dump-dir", default=str(ROOT / "server" / "cps_dump"))
    ap.add_argument("--arg", dest="game_args", default=DEFAULT_ARG, help="传给客户端的参数")
    ap.add_argument("--extra-args", dest="extra_args", default="",
                    help="额外命令行参数（空格分隔，逐个作为独立 argv 传入）。"
                         "例：--extra-args cpsoff —— 客户端 0x5836xx 见到以 cpsoff 开头的参数"
                         "会置 [0x117B7A0]=1 并完全不加载 ACOPCShell.dll")
    ap.add_argument("--no-elevate", action="store_true")
    ap.add_argument("--kill", action="store_true", help="超时后杀掉目标进程")
    ap.add_argument("--fresh", action="store_true", default=True, help="清空上次日志（默认开）")
    ap.add_argument("--no-fresh", dest="fresh", action="store_false", default=argparse.SUPPRESS,
                    help="追加写 server/hook_log.txt，不删除旧日志。"
                         "沙箱/文件被占用时 Path.unlink() 会失败，用这个跳过清理")
    ap.add_argument("--attach", type=int, default=None, help="改为 attach 到已存在的 PID，不 spawn")
    ap.add_argument("--selftest", action="store_true",
                    help="注入 32 位 notepad.exe 验证 hook 脚本本身能否加载（不涉及游戏）")
    ap.add_argument("--device-version", type=lambda x: int(x, 0), default=0x804,
                    help="IOCTL 0x222059 返回的 4 字节'保护/驱动版本'，模块疑似拿它比对 0x404/0x804/0xC04/0x411（默认 0x804）")
    ap.add_argument("--no-clean", action="store_true",
                    help="启动前不清理上一轮留下的 CPS 服务键/驱动（默认会清，保证可复现）")
    ap.add_argument("--out-file", default=None,
                    help="把控制台输出同时写一份到这个文件（提权子进程用）")
    ap.add_argument("--no-dpi-fix", action="store_true",
                    help="不给子进程加 __COMPAT_LAYER=HIGHDPIAWARE（用于对照实验）")
    ap.add_argument("--deep-trace", action="store_true",
                    help="额外记录 VirtualAlloc/VirtualProtect（量极大，平时关掉）")
    ap.add_argument("--script", default=None,
                    help="改用指定的 frida 脚本（默认 tools/xgg_hook.js）。"
                         "传一个几乎空白的脚本可以用来对照：Themida 反虚拟机弹窗到底是"
                         "「frida 存在本身」触发的，还是「我们 hook 了某个 API」触发的。")
    ap.add_argument("--pilot-hook", action="store_true",
                    help="额外加载 tools/pilot_hook.js：只读观测 0xE13A 解析进度")
    ap.add_argument("--idle-script", action="store_true",
                    help="等价于 --script tools/noop_hook.js")
    ap.add_argument("--skip-dlls", default="",
                    help="逗号分隔的 dll 名，这些 dll 上的 hook 全部不装（二分定位用）")
    ap.add_argument("--skip-names", default="",
                    help="逗号分隔的 'dll!Export'，这些导出不 hook（二分定位用）")
    ap.add_argument("--full", action="store_true",
                    help="关掉最小必要集白名单，把全部 hook 都装上（诊断用；"
                         "大概率会触发 Themida 的虚拟机检测）")
    ap.add_argument("--hook-ws2", action="store_true",
                    help="最小集模式下也挂 ws2_32 的 connect/send/recv 等（看它连哪台服务器）")
    ap.add_argument("--ioctl-out", default=None,
                    help='精确指定某个 IOCTL 的输出字节，如 '
                         '"0x222055=0408000000000000"（多个用逗号分隔）。'
                         "默认 0x222055 用 @read:ptr：按入参 addr/len 真读进程内存，"
                         "再把缓冲地址写回输出。还支持 @read:inline / @alloc:<n>")
    ap.add_argument("--veh", action="store_true",
                    help="用 VEH 记录崩溃现场（寄存器/栈/指令字节）。"
                         "不拦截异常，只观察；不修改任何 API 入口字节，不会触发 Themida 检测")
    ap.add_argument("--probe-table", action="store_true",
                    help="装数据表下载的内部探针：0x544790 处理入口 / 0xA46480 正文转 wide 的返回 / "
                         "0x544DD7 推进 / 0x544E07 清理退出。只记录，不改返回值。"
                         "用来判定回包被拒到底是正文转换失败还是表加载抛异常")
    ap.add_argument("--scan-rtti", type=float, default=0.0, metavar="SEC",
                    help="启动 SEC 秒后只读扫描内存里的模块清单与 MSVC RTTI 类名"
                         "（.?AV / .??_7），用于在双层壳下白拿一份类名地图。"
                         "建议 20~40；0 = 关闭")
    ap.add_argument("--dump-image", action="store_true",
                    help="扫描时把主模块解包镜像与匿名 r-x 段整段 dump 到 "
                         "server/img_dump/，供离线反汇编（IDA/Ghidra）。"
                         "需要配合 --scan-rtti 指定时点")
    ap.add_argument("--scan-str", default=None, metavar="KW1,KW2",
                    help="同时扫描这些关键字的字符串（自动试 GBK/UTF-16LE/UTF-8），"
                         "找到后再在代码区反查引用它们的指令地址。"
                         '例如 "请选择战区,技术测试区,authsv"')
    ap.add_argument("--keep-existing", action="store_true",
                    help="不要清理已经在跑的客户端进程（默认会清，因为同一时间只允许一个客户端）")
    ap.add_argument("--redirect-connect", default=None, metavar="IP:PORT",
                    help='把所有非本机的 connect 目标改写到这个地址，例如 '
                         '"127.0.0.1:30000"。实测客户端会去连外网游戏服 '
                         '60.206.12.127:30000（重试 11 次后放弃），配合 '
                         'server/world_sniff.py 就能看到它发的第一个包')
    ap.add_argument("--http-to", default=None, metavar="IP:PORT",
                    help='劫持 WinHttpConnect 的目标到本地 HTTP 服务，例如 '
                         '"127.0.0.1:8080"。客户端会去取 '
                         'http://ms.patch1.9you.com/launcher/authsv.csv（战区/服务器'
                         '清单），配合 server/fake_http.py 就能伪造它')
    ap.add_argument("--retry", type=int, default=1,
                    help="允许重试次数。实测进程有一定概率在 5~15s 内挂在保护模块的"
                         "工作线程里（region+0x27d71/0x27d9f 的环形队列出队）；"
                         "早退就清掉 CPS 残留重来一轮，直到活过 --seconds 为止。"
                         "建议配合 --seconds 1800 使用")
    args = ap.parse_args()

    if os.name != "nt":
        print("仅 Windows。", file=sys.stderr)
        return 2

    if not args.no_elevate:
        elevate_self()

    # 到这里说明已经是提权后的实例（父进程在 elevate_self 里就退了）
    if args.out_file:
        try:
            p = Path(args.out_file)
            if not p.is_absolute():
                p = ROOT / p
            p.parent.mkdir(parents=True, exist_ok=True)
            _fh = p.open("w", encoding="utf-8", buffering=1)

            class _Tee:
                def __init__(self, *streams):
                    self.streams = streams

                def write(self, d):
                    for s in self.streams:
                        try:
                            s.write(d)
                        except Exception:  # noqa: BLE001
                            pass
                    return len(d)

                def flush(self):
                    for s in self.streams:
                        try:
                            s.flush()
                        except Exception:  # noqa: BLE001
                            pass

                def isatty(self):
                    return False

            sys.stdout = _Tee(sys.__stdout__, _fh)
            sys.stderr = _Tee(sys.__stderr__, _fh)
        except Exception as e:  # noqa: BLE001
            print(f"[!] 无法打开输出文件 {args.out_file}: {e}")

    try:
        import frida
    except ImportError:
        print("缺少 frida。请先安装：\n"
              '  "C:/Users/86186/.workbuddy/binaries/python/envs/default/Scripts/python.exe" -m pip install frida',
              file=sys.stderr)
        return 3

    if args.selftest:
        exe = Path(r"C:\Windows\SysWOW64\notepad.exe")
        args.game_args = ""
        args.seconds = min(args.seconds, 6.0)
        args.no_elevate = True
    else:
        exe = find_exe()
    cfg = build_cfg(args)
    Path(cfg["dumpDir"]).mkdir(parents=True, exist_ok=True)

    if not getattr(args, "keep_existing", False):
        kill_stale_runners()
        kill_existing_game()

    if not args.no_clean and clean_cps is not None:
        print("[*] 清理上一轮的 CPS 残留（服务键/驱动文件）……")
        try:
            clean_cps.clean()
        except Exception as e:
            print(f"[!] 清理失败（继续）: {e}")

    js_path = JS_PATH
    if args.idle_script:
        js_path = JS_PATH.with_name("noop_hook.js")
    elif args.script:
        js_path = Path(args.script)
        if not js_path.is_absolute():
            js_path = (ROOT / args.script).resolve()
    js = js_path.read_text(encoding="utf-8").replace("__CFG_JSON__", json.dumps(cfg))
    logger = Logger(LOG_PATH, args.fresh)

    print("=" * 68)
    print(" frida", frida.__version__, "| 目标:", exe)
    print(" 脚本:", js_path.name)
    print(" hook 集:", "全开（--full）" if args.full else f"最小必要集（{len(MINIMAL_HOOKS)} 个）")
    print(" 伪造:", {k: v for k, v in cfg["fake"].items() if v} or "（无，纯记录）")
    print(" 驱动捕获目录:", cfg["dumpDir"])
    print(" 日志:", LOG_PATH)
    print("=" * 68)

    def _attempt(idx: int) -> str:
        """跑一轮。返回 'ok'（活过整个观察窗口）/ 'early'（进程自己退了）。"""
        if idx > 1:
            print(f"\n[*] ===== 第 {idx} 次尝试 =====")
            if not args.no_clean and clean_cps is not None:
                try:
                    clean_cps.clean()
                except Exception as e:
                    print(f"[!] 清理失败（继续）: {e}")
        device = frida.get_local_device()
        pid = args.attach
        spawned = False
        spawn_env = None
        if pid is None:
            # 关键修复：让游戏进程变成 DPI 感知。
            # 非 DPI 感知时 GetSystemMetrics(0/1) 返回"逻辑分辨率"（本机 1920x1080
            # 桌面 + 125% 缩放 -> 1536x864），而游戏用 EnumDisplaySettings 拿到物理
            # 1920x1080 存进配置对象，两者一比较 -> "屏幕分辨率小于要求的尺寸"。
            # 加 HIGHDPIAWARE 兼容层后 GetSystemMetrics 直接返回物理像素。
            if not args.no_dpi_fix:
                spawn_env = dict(os.environ)
                layer = spawn_env.get("__COMPAT_LAYER", "").strip()
                if "HIGHDPIAWARE" not in layer.upper():
                    spawn_env["__COMPAT_LAYER"] = (layer + " HIGHDPIAWARE").strip()
                print(f"[*] DPI 修复: __COMPAT_LAYER={spawn_env['__COMPAT_LAYER']!r}")
            print(f"[*] 挂起启动: {exe}  arg={args.game_args!r} extra={getattr(args, 'extra_args', '')!r}  cwd={exe.parent}")
            argv = [str(exe)] + ([args.game_args] if args.game_args else [])
            argv += [s for s in (getattr(args, "extra_args", "") or "").split() if s]
            if spawn_env is not None:
                pid = device.spawn(str(exe), argv=argv, cwd=str(exe.parent), env=spawn_env)
            else:
                pid = device.spawn(str(exe), argv=argv, cwd=str(exe.parent))
            spawned = True
            print(f"[*] pid = {pid}")
        else:
            print(f"[*] attach 到 pid = {pid}")

        session = device.attach(pid)
        detached = {"flag": False, "reason": None}
        session.on("detached", lambda reason, *a: (detached.update(flag=True, reason=reason), None))

        script = session.create_script(js)
        script.on("message", logger.handle)
        script.load()

        # --pilot-hook：只读观测 0xE13A 解析进度（机师列表）。失败不影响主流程。
        if getattr(args, 'pilot_hook', False):
            try:
                pjs = (ROOT / 'tools' / 'pilot_hook.js').read_text(encoding='utf-8')
                pscript = session.create_script(pjs)
                pscript.on("message", logger.handle)
                pscript.load()
                print("[*] pilot_hook 已加载（只读观测 0xE13A 解析进度）")
            except Exception as e:  # noqa: BLE001
                print(f"[!] pilot_hook 加载失败（忽略）: {e}")
        if spawned:
            device.resume(pid)
            print("[*] 已恢复运行，开始记录……\n")

        deadline = time.monotonic() + args.seconds
        texts: list[str] = []
        while time.monotonic() < deadline and not detached["flag"]:
            time.sleep(0.5)
            if spawned:
                for t in collect_window_texts(pid):
                    if t not in texts:
                        texts.append(t)
                        print(f"[窗口] {t}")

        print("\n" + "-" * 68)
        if detached["flag"]:
            print(f"[=] 目标进程已退出，reason={detached['reason']}")
        else:
            print(f"[=] 观察时间到（{args.seconds:.0f}s），进程仍在运行")
            if args.kill:
                try:
                    device.kill(pid)
                    print("[=] 已按 --kill 结束进程")
                except Exception as e:
                    print(f"[=] kill 失败: {e}")

        # 必须在 unload/detach 之前定格"是否活着"：下面的 session.detach() 本身
        # 也会触发 detached 事件，否则活满窗口也会被误判成"早退"。
        alive = not detached["flag"]

        ec = query_exit_code(pid)
        if ec is not None and ec != 259:
            print(f"[=] 退出码 = {ec} (0x{ec & 0xFFFFFFFF:x})")
        if texts:
            print("[=] 捕获到的窗口文字:")
            for t in texts:
                print("     ", t.replace("\n", " | "))

        # 目标可能还活着（这其实是好事），unload/detach 有概率卡住，放到线程里限时等
        import threading

        def _quiet(fn) -> None:
            try:
                fn()
            except Exception:
                pass

        for fn in (script.unload, session.detach):
            th = threading.Thread(target=_quiet, args=(fn,), daemon=True)
            th.start()
            th.join(3.0)

        print(f"[=] 本轮共记录 {logger.count} 条事件；抓到 {len(logger.dumps)} 个驱动文件")
        return "ok" if alive else "early"

    tries = max(1, int(args.retry))
    if tries > 1:
        print(f"[*] 允许重试：最多 {tries} 次；只要进程没活到 {args.seconds:.0f}s 就算失败、重来一轮。")
    for i in range(1, tries + 1):
        result = _attempt(i)
        if result == "ok":
            if i > 1:
                print(f"\n[+] 第 {i} 次尝试成功：进程活过了整个观察窗口。")
            break
        if i < tries:
            print(f"[-] 第 {i} 次尝试早退，准备重试……")
        else:
            print(f"[-] 已用完 {tries} 次尝试，最后一次也早退了。")

    if clean_cps is not None:
        info, files = clean_cps.inspect()
        in_scm = False
        try:
            in_scm = clean_cps.scm_exists()
        except Exception:
            pass
        if info or files or in_scm:
            print(f"[!] 注意：仍有 CPS 残留 {'(SCM 里还在)' if in_scm else ''} {info or ''} {files or ''}"
                  f"，可跑 python tools/clean_cps.py")
    logger.close()
    print(f"[=] 累计记录 {logger.count} 条事件；抓到 {len(logger.dumps)} 个驱动文件")
    for d in logger.dumps:
        print(f"    {d}")
    if not logger.dumps:
        print("    （没抓到驱动。可能 StartService 之前它还没落盘，或路径不在这几个候选里）")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    raise SystemExit(main())
