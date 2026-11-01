#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
假 HTTP 服务：接住客户端对 ms.patch1.9you.com 的请求（尤其 /launcher/authsv.csv）。

用途
----
客户端点"登录"时会去取：
    http://ms.patch1.9you.com/launcher/authsv.csv?t=<随机>
这个 CSV 就是**战区 / 服务器清单**（"技术测试区" 就是这么来的），
也是 60.206.12.127:30000 的来源。真域名已死，所以我们在 API 层把它劫持到本地：
    run_hooked.py --http-to 127.0.0.1:8080
然后由本脚本按 server/fake_root/ 下的静态文件应答。

用法
----
    python server/fake_http.py --port 8080
    # 把所有请求（含 query）都记到 server/fake_http.log，便于反推格式

静态根目录：server/fake_root/
    launcher/authsv.csv   ->  /launcher/authsv.csv 的应答体

任何以 .csv 结尾的请求按 GBK 或 UTF-8 原样回；找不到文件回 404（但会记录）。
"""
from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAKE_ROOT = ROOT / "server" / "fake_root"
LOG_PATH = ROOT / "server" / "fake_http.log"
_loglock = threading.Lock()


def log(line: str) -> None:
    ts = time.strftime("%H:%M:%S")
    with _loglock:
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(f"{ts} {line}\n")
        print(f"{ts} {line}", flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx/1.14.0"   # 装得像点，某些客户端会挑 UA/Server

    def log_message(self, fmt, *args):   # 静音默认 stderr 日志
        pass

    def _resolve(self):
        # 去掉 query
        path = self.path.split("?", 1)[0]
        path = path.lstrip("/")
        if not path:
            path = "launcher/authsv.csv"
        # 防目录穿越
        target = (FAKE_ROOT / path).resolve()
        try:
            target.relative_to(FAKE_ROOT.resolve())
        except ValueError:
            return None
        return target

    def _dump_req(self):
        hdrs = " | ".join(f"{k}: {v}" for k, v in self.headers.items())
        log(f"REQ {self.command} {self.path}  [{hdrs}]")

    def _serve(self, body: bytes | None, code: int = 200,
               ctype: str = "text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body or b"")))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        self._dump_req()
        target = self._resolve()
        if target and target.is_file():
            data = target.read_bytes()
            ctype = "text/csv; charset=utf-8" if target.suffix == ".csv" else "application/octet-stream"
            log(f"  -> 200 {target.name} {len(data)}B")
            self._serve(data, 200, ctype)
        else:
            log(f"  -> 404 (未找到 {target})")
            self._serve(b"not found", 404)

    def do_POST(self):
        self._dump_req()
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        if body:
            log(f"  body({n}B) hex={body[:512].hex()}")
            try:
                log(f"  body text={body[:512].decode('utf-8', 'replace')}")
            except Exception:
                pass
        target = self._resolve()
        if target and target.is_file():
            data = target.read_bytes()
            ctype = "text/csv; charset=utf-8" if target.suffix == ".csv" else "application/octet-stream"
            log(f"  -> 200(POST) {target.name} {len(data)}B")
            self._serve(data, 200, ctype)
        else:
            log(f"  -> 404(POST) (未找到 {target})")
            self._serve(b"not found", 404)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    FAKE_ROOT.mkdir(parents=True, exist_ok=True)
    if LOG_PATH.exists():
        LOG_PATH.unlink()

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    log(f"listening on {args.host}:{args.port}（静态根 {FAKE_ROOT}）")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
