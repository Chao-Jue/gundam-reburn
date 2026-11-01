"""Local endpoints for the 9you China Gundam Online client.

Two listeners:

* HTTP, default 127.0.0.1:8766. patcher.exe fetches a hardcoded URL,
  originally http://ms.patch1.9you.com/ms_patch.ini. The body is ASCII
  text which the patcher widens to UTF-16 and splits on double quotes.
  Field 1 is a decimal version compared with UserVersion.dat. Field 2
  is the download base and is given a trailing slash if it lacks one.
  Later fields of the form "id#relative/path" are individual files.
  When field 1 equals the installed version, the patcher does not
  download those files.

* TCP, default 127.0.0.1:1634. sysinfo.ini names this as
  Target_Url / Target_port (originally ng.9you.com:1634). Ng.dll sends
  MINFO, ALREQ and RNREQ. The listener answers MBACK, ALACK and RNACK.

--point-client rewrites those two local pointers and keeps the originals
beside them (patcher.exe.official, sysinfo.ini.official).
--restore-client copies the backups back.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socketserver import StreamRequestHandler, ThreadingTCPServer
from urllib.parse import unquote

LOG_PATH = Path(__file__).with_name("cn_requests.log")
GATE_HOST = "ng.9you.com"


def log(line: str) -> None:
    stamp = datetime.now().strftime("%H:%M:%S")
    text = f"{stamp} {line}"
    print(text, flush=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(text + "\n")


def find_client(explicit: Path | None) -> Path:
    if explicit:
        return explicit
    here = Path(__file__).resolve().parents[1]
    found = list(here.rglob("GundamOnline_CHINA.exe"))
    if not found:
        raise SystemExit("GundamOnline_CHINA.exe not found; pass --client")
    return found[0].parent


def read_user_version(client: Path) -> int:
    data = (client / "UserVersion.dat").read_bytes()
    if len(data) < 4:
        raise SystemExit(f"UserVersion.dat is {len(data)} bytes")
    return struct.unpack_from("<I", data, 0)[0]


def patch_ini(version: int, origin: str) -> bytes:
    base = origin.rstrip("/") + "/patch_files/release/"
    # Two quoted fields. Further "id#path" fields would be downloads.
    return f'"{version}""{base}"\r\n'.encode("utf-16le")


PATCH_URLS = (
    "http://ms.patch1.9you.com/ms_patch.ini",
    "http://ms.patch1.9you.com/ms_patch_classic.ini",
)


def rewrite_utf16_url(blob: bytearray, old: str, new: str) -> bool:
    if len(new) > len(old):
        raise SystemExit(f"replacement URL is longer than the built-in one: {new}")
    encoded_old = old.encode("utf-16le")
    encoded_new = new.encode("utf-16le") + b"\x00\x00"
    at = blob.find(encoded_old)
    if at < 0:
        return False
    blob[at : at + len(encoded_new)] = encoded_new
    return True


def point_client(client: Path, origin: str) -> None:
    root = Path(__file__).resolve().parents[1] / "launcher"
    origin = origin.rstrip("/")
    for patcher in root.rglob("patcher.exe"):
        backup = patcher.with_name("patcher.exe.official")
        if not backup.exists():
            backup.write_bytes(patcher.read_bytes())
        blob = bytearray(backup.read_bytes())
        changed = False
        for old in PATCH_URLS:
            name = old.rsplit("/", 1)[-1]
            changed = rewrite_utf16_url(blob, old, f"{origin}/{name}") or changed
        if changed:
            try:
                patcher.write_bytes(blob)
            except PermissionError:
                log(f"skipped locked {patcher}")
                continue
            log(f"pointed {patcher}")
    for sysinfo in root.rglob("sysinfo.ini"):
        backup = sysinfo.with_name("sysinfo.ini.official")
        if not backup.exists():
            backup.write_bytes(sysinfo.read_bytes())
        text = backup.read_bytes().replace(GATE_HOST.encode("ascii"), b"127.0.0.1")
        if text != sysinfo.read_bytes():
            sysinfo.write_bytes(text)
            log(f"pointed {sysinfo}")


def restore_client(client: Path) -> None:
    root = Path(__file__).resolve().parents[1] / "launcher"
    found = list(root.rglob("*.official"))
    if not found:
        print("no backups")
        return
    for backup in found:
        target = backup.with_name(backup.name.removesuffix(".official"))
        target.write_bytes(backup.read_bytes())
        print(f"restored {target}")


def ng_packet(cmd: str, count: int, extra: bytes = b"") -> bytes:
    name = cmd.encode("ascii")
    name = name + b"\x00" * (8 - len(name))
    total = 16 + len(extra)
    return name + struct.pack("<II", total, count) + extra


def gate_reply(data: bytes) -> bytes | None:
    cmd = data[:8].split(b"\x00", 1)[0]
    if cmd == b"MINFO":
        # count 0, then the status dword the parser reads at offset 16
        return ng_packet("MBACK", 0, struct.pack("<I", 0))
    if cmd == b"ALREQ":
        return ng_packet("ALACK", 0)
    if cmd == b"RNREQ":
        return ng_packet("RNACK", 0)
    return None


def recv_exact(conn, size: int) -> bytes:
    buf = b""
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


class GateHandler(StreamRequestHandler):
    def handle(self) -> None:
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        self.connection.settimeout(15)
        try:
            head = recv_exact(self.connection, 12)
            if len(head) < 12:
                log(f"gate {peer} short header {len(head)}")
                return
            total = struct.unpack_from("<I", head, 8)[0]
            if total < 12 or total > 0x2800:
                log(f"gate {peer} bad length {total}")
                return
            data = head + recv_exact(self.connection, total - 12)
        except TimeoutError:
            log(f"gate {peer} timeout")
            return
        except OSError as exc:
            log(f"gate {peer} recv error {exc}")
            return
        cmd = data[:8].split(b"\x00", 1)[0].decode("ascii", "replace")
        reply = gate_reply(data)
        log(f"gate {peer} {cmd} {len(data)} bytes -> {len(reply) if reply else 0}")
        if reply is None:
            return
        try:
            self.connection.sendall(reply)
            self.connection.shutdown(socket.SHUT_WR)
        except OSError as exc:
            log(f"gate {peer} send error {exc}")


class PatchHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "cn-patch"

    def log_message(self, fmt: str, *args) -> None:
        log(f"http {self.address_string()} {fmt % args}")

    def do_HEAD(self) -> None:
        self._serve(head=True)

    def do_GET(self) -> None:
        self._serve(head=False)

    def _serve(self, head: bool) -> None:
        path = unquote(self.path.split("?", 1)[0])
        client: Path = self.server.client_root  # type: ignore[attr-defined]
        origin: str = self.server.origin  # type: ignore[attr-defined]
        version: int = self.server.user_version  # type: ignore[attr-defined]
        if path in ("/ms_patch.ini", "/"):
            body = patch_ini(version, origin)
            self._send(200, "text/plain", body, head)
            return
        prefix = "/patch_files/release/"
        if path.startswith(prefix):
            rel = path[len(prefix) :].replace("/", "\\").lstrip("\\")
            target = (client / rel).resolve()
            if client.resolve() not in target.parents and target != client.resolve():
                self._send(403, "text/plain", b"outside client\n", head)
                return
            if target.is_file():
                self._send(200, "application/octet-stream", target.read_bytes(), head)
                return
            self._send(404, "text/plain", f"missing {rel}\n".encode(), head)
            return
        self._send(404, "text/plain", b"not found\n", head)

    def _send(self, code: int, content_type: str, body: bytes, head: bool) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if not head:
            self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="China client patch + gate logger")
    parser.add_argument("--client", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=8766)
    parser.add_argument("--gate-port", type=int, default=1634)
    parser.add_argument("--point-client", action="store_true")
    parser.add_argument("--restore-client", action="store_true")
    args = parser.parse_args()
    client = find_client(args.client)
    if args.restore_client:
        restore_client(client)
        return
    origin = f"http://{args.host}:{args.http_port}"
    if args.point_client:
        point_client(client, origin)
        return
    version = read_user_version(client)
    log(f"client {client}")
    log(f"UserVersion {version}")
    log(f"ini {patch_ini(version, origin).decode()}")

    httpd = ThreadingHTTPServer((args.host, args.http_port), PatchHandler)
    httpd.client_root = client  # type: ignore[attr-defined]
    httpd.origin = origin  # type: ignore[attr-defined]
    httpd.user_version = version  # type: ignore[attr-defined]
    gate = ThreadingTCPServer((args.host, args.gate_port), GateHandler)
    threading.Thread(target=gate.serve_forever, daemon=True).start()
    log(f"http://{args.host}:{args.http_port}/ms_patch.ini")
    log(f"gate {args.host}:{args.gate_port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        gate.shutdown()


if __name__ == "__main__":
    main()
