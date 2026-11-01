"""在本地监听游戏服端口，把客户端发来的字节原样记下来。

背景：客户端过了 gate(1634) 之后会去连真正的游戏服 —— 实测
`60.206.12.127:30000`（每 3 秒重试，11 次后放弃）。该地址在客户端目录里
搜不到明文/二进制，只能在 API 层改，所以配合：

    tools/run_hooked.py --hook-ws2 --redirect-connect 127.0.0.1:30000

本脚本负责接住这个连接，并把第一个包的内容（hex + ascii）打出来，
方便判断它是"客户端先发"还是"等服务器先发"。

用法：
    python server/world_sniff.py                     # 只记录，不回任何东西
    python server/world_sniff.py --port 30000
    python server/world_sniff.py --send 0a0b0c       # 收到连接后先回这段 hex
    python server/world_sniff.py --reply-to <模式>   # 见 --help
"""

from __future__ import annotations

import argparse
import socket
import threading
from datetime import datetime
from pathlib import Path

LOG_PATH = Path(__file__).with_name("world_sniff.log")
LOCK = threading.Lock()


def log(line: str) -> None:
    stamp = datetime.now().strftime("%H:%M:%S")
    text = f"{stamp} {line}"
    print(text, flush=True)
    with LOCK:
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(text + "\n")


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    out = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"    {base + off:08x}  {hexpart:<{width * 3}}  {ascii_part}")
    return "\n".join(out)


def handle(conn: socket.socket, addr, args) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    log(f"accept {peer}")
    conn.settimeout(args.idle)
    total = 0
    try:
        if args.send:
            payload = bytes.fromhex(args.send.replace(" ", ""))
            conn.sendall(payload)
            log(f"sent {len(payload)} bytes to {peer}:\n{hexdump(payload)}")
        while True:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                log(f"idle timeout on {peer} (收不到更多数据)")
                break
            if not data:
                log(f"peer {peer} closed after {total} bytes")
                break
            log(f"recv {len(data)} bytes from {peer} (累计 {total + len(data)}):\n"
                f"{hexdump(data, total)}")
            total += len(data)
    except OSError as exc:
        log(f"peer {peer} error {exc}")
    finally:
        try:
            conn.close()
        except OSError:
            pass
        log(f"closed {peer}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=30000)
    ap.add_argument("--send", default=None,
                    help="accept 之后先发这段 hex（有些协议要求服务器先开口）")
    ap.add_argument("--idle", type=float, default=20.0, help="空闲多久就断开（秒）")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((args.host, args.port))
    except OSError as exc:
        print(f"[X] 绑定 {args.host}:{args.port} 失败: {exc}", flush=True)
        return 1
    srv.listen(8)
    log(f"listening on {args.host}:{args.port}（日志 {LOG_PATH}）")
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr, args), daemon=True).start()
    except KeyboardInterrupt:
        log("停")
    finally:
        srv.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
