"""Local patch endpoint for the Gundam Online client.

The installed client keeps its update location in list/filelist.dat:

    "BaseURL","http://patch.msgo.bno.jp/patchmsgo/files/<token>/"

That host is not present in GundamOnline.exe (the executable is packed).
This process serves the same list and the files already on disk, and can
point the client's BaseURL at itself. Official zip blobs are not part of
an extracted install; an up-to-date client checks per-file SHA1 and does
not need them.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


OFFICIAL_HOST = "patch.msgo.bno.jp"
LOG_PATH = Path(__file__).with_name("patch_requests.log")


@dataclass
class FileEntry:
    path: str
    size: int
    sha1: str
    container: str


@dataclass
class FileList:
    raw: bytes
    base_url: str
    token: str
    files: list[FileEntry] = field(default_factory=list)
    packages: dict[str, FileEntry] = field(default_factory=dict)

    @property
    def prefix(self) -> str:
        return f"patchmsgo/files/{self.token}/"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_client() -> Path:
    return repo_root() / "GundamOnline"


def load_filelist(client: Path) -> FileList:
    path = client / "list" / "filelist.dat"
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    rows = list(csv.reader(io.StringIO(text)))
    if not rows or rows[0][:2] != ["ID", "Data"]:
        raise SystemExit(f"unexpected filelist header: {path}")

    base_url = ""
    files: list[FileEntry] = []
    packages: dict[str, FileEntry] = {}
    for row in rows[1:]:
        if not row:
            continue
        if row[0] == "BaseURL":
            base_url = row[1] if len(row) > 1 else ""
            continue
        if len(row) < 8:
            continue
        ident, data, size_s, _time, sha1, _comment, _no_update, container = row[:8]
        try:
            size = int(size_s)
        except ValueError:
            continue
        entry = FileEntry(data.replace("\\", "/"), size, sha1.lower(), container)
        if ident:
            packages[entry.path] = entry
        else:
            files.append(entry)

    if not base_url:
        raise SystemExit(f"BaseURL missing from {path}")
    parsed = urlparse(base_url)
    token = parsed.path.rstrip("/").split("/")[-1]
    if not token:
        raise SystemExit(f"could not read patch token from {base_url}")
    return FileList(raw, base_url, token, files, packages)


def origin_for(host: str, port: int) -> str:
    shown = host if host not in ("0.0.0.0", "") else "127.0.0.1"
    return f"http://{shown}:{port}"


def rewrite_baseurl(raw: bytes, origin: str, token: str) -> bytes:
    new_url = f"{origin}/patchmsgo/files/{token}/".encode("ascii")
    lines = raw.splitlines(keepends=True)
    replaced = False
    out: list[bytes] = []
    for line in lines:
        if not replaced and line.startswith(b'"BaseURL"'):
            mark = line.find(b'","')
            if mark < 0:
                raise SystemExit("BaseURL line has no URL field")
            rest = line[mark + 3 :]
            end = rest.find(b'"')
            if end < 0:
                raise SystemExit("BaseURL line is not closed")
            line = line[: mark + 3] + new_url + rest[end:]
            replaced = True
        out.append(line)
    if not replaced:
        raise SystemExit("BaseURL line not found")
    return b"".join(out)


def point_client(client: Path, origin: str, listing: FileList) -> str:
    path = client / "list" / "filelist.dat"
    backup = client / "list" / "filelist.dat.official"
    if not backup.exists():
        backup.write_bytes(path.read_bytes())
    updated = rewrite_baseurl(backup.read_bytes(), origin, listing.token)
    if path.read_bytes() != updated:
        path.write_bytes(updated)
    new_url = f"{origin}/patchmsgo/files/{listing.token}/"
    return new_url


def restore_client(client: Path) -> None:
    path = client / "list" / "filelist.dat"
    backup = client / "list" / "filelist.dat.official"
    if not backup.exists():
        raise SystemExit(f"no backup at {backup}")
    path.write_bytes(backup.read_bytes())
    print(f"restored {path}")


def audit(client: Path, listing: FileList) -> int:
    missing: list[str] = []
    mismatch: list[str] = []
    hashed = 0
    total = len(listing.files)
    for index, entry in enumerate(listing.files, start=1):
        target = client / Path(entry.path)
        if not target.is_file():
            missing.append(entry.path)
            continue
        size = target.stat().st_size
        if size != entry.size:
            mismatch.append(f"{entry.path} size {size} != {entry.size}")
            continue
        digest = hashlib.sha1()
        with target.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        hashed += 1
        if digest.hexdigest() != entry.sha1:
            mismatch.append(f"{entry.path} sha1 {digest.hexdigest()} != {entry.sha1}")
        if index % 200 == 0 or index == total:
            print(f"checked {index}/{total}", flush=True)
    print(f"files {total} hashed {hashed} missing {len(missing)} mismatch {len(mismatch)}")
    for item in missing[:30]:
        print("missing", item)
    for item in mismatch[:30]:
        print("mismatch", item)
    if len(missing) > 30:
        print(f"... {len(missing) - 30} more missing")
    if len(mismatch) > 30:
        print(f"... {len(mismatch) - 30} more mismatches")
    return 1 if missing or mismatch else 0


class PatchHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "GundamReburnPatch/0.1"

    listing: FileList
    client: Path
    origin: str
    log_lock: threading.Lock
    log_file: object

    def log_message(self, fmt: str, *args) -> None:
        return

    def _log(self, status: int, extra: str = "") -> None:
        line = (
            f"{datetime.now().isoformat(timespec='seconds')} "
            f"{self.client_address[0]} {self.command} {self.path} {status}"
        )
        if extra:
            line += " " + extra
        agent = self.headers.get("User-Agent", "")
        if agent:
            line += f" ua={agent}"
        print(line, flush=True)
        with self.log_lock:
            self.log_file.write(line + "\n")

    def do_HEAD(self) -> None:
        self._respond(write_body=False)

    def do_GET(self) -> None:
        self._respond(write_body=True)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(min(length, 65536)) if length else b""
        preview = body[:200].decode("utf-8", "replace").replace("\n", " ")
        self._respond(write_body=True, extra=f"post={preview}" if preview else "")

    def _respond(self, write_body: bool, extra: str = "") -> None:
        rel = unquote(urlparse(self.path).path).lstrip("/")
        token_prefix = self.listing.prefix
        for prefix in (token_prefix, "patchmsgo/files/", "patchmsgo/", "list/"):
            if rel.startswith(prefix):
                rel = rel[len(prefix) :]
                break
        rel = rel.lstrip("/")

        if rel in ("", "filelist.dat"):
            body = rewrite_baseurl(self.listing.raw, self.origin, self.listing.token)
            # Serve the on-disk list when it already points at us, so the
            # bytes match what --point-client wrote.
            on_disk = (self.client / "list" / "filelist.dat").read_bytes()
            if f"{self.origin}/patchmsgo/files/{self.listing.token}/".encode() in on_disk:
                body = on_disk
            self._send_bytes(body, "text/plain; charset=utf-8", write_body, extra or "filelist")
            return

        if rel in self.listing.packages:
            self._send_status(404, f"package {rel} is not stored in the install", write_body, extra)
            return

        target = (self.client / Path(rel)).resolve()
        try:
            target.relative_to(self.client.resolve())
        except ValueError:
            self._send_status(403, "path escapes client directory", write_body, extra)
            return
        if not target.is_file():
            self._send_status(404, "not in client", write_body, extra)
            return
        self._send_file(target, write_body, extra)

    def _send_status(self, status: int, message: str, write_body: bool, extra: str) -> None:
        payload = (message + "\n").encode("utf-8")
        self._log(status, (extra + " " + message).strip())
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload) if write_body else 0))
        self.send_header("Connection", "close")
        self.end_headers()
        if write_body:
            self.wfile.write(payload)

    def _send_bytes(self, payload: bytes, content_type: str, write_body: bool, extra: str) -> None:
        self._log(200, extra or f"bytes={len(payload)}")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        if write_body:
            self.wfile.write(payload)

    def _send_file(self, target: Path, write_body: bool, extra: str) -> None:
        size = target.stat().st_size
        start, end = 0, size - 1
        status = 200
        range_header = self.headers.get("Range")
        if range_header and range_header.startswith("bytes="):
            spec = range_header.split("=", 1)[1].split(",", 1)[0].strip()
            left, _, right = spec.partition("-")
            try:
                if left == "":
                    length = int(right)
                    start = max(size - length, 0)
                else:
                    start = int(left)
                    end = int(right) if right else size - 1
            except ValueError:
                start, end = 0, size - 1
            else:
                if start >= size or start > end:
                    self._log(416, extra)
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{size}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                end = min(end, size - 1)
                status = 206

        length = 0 if size == 0 else end - start + 1
        self._log(status, (extra + f" file={target.name} {length}").strip())
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(length if write_body else 0))
        self.send_header("Accept-Ranges", "bytes")
        if status == 206:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.send_header("Connection", "close")
        self.end_headers()
        if not write_body or length == 0:
            return
        remaining = length
        with target.open("rb") as handle:
            handle.seek(start)
            while remaining:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)


def serve(client: Path, host: str, port: int, listing: FileList) -> None:
    origin = origin_for(host, port)
    log_file = LOG_PATH.open("a", encoding="utf-8", buffering=1)
    lock = threading.Lock()

    class Handler(PatchHandler):
        pass

    Handler.listing = listing
    Handler.client = client
    Handler.origin = origin
    Handler.log_lock = lock
    Handler.log_file = log_file

    ThreadingHTTPServer.allow_reuse_address = True
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"listening on {origin}", flush=True)
    print(f"filelist at {origin}/patchmsgo/files/{listing.token}/filelist.dat", flush=True)
    print(f"logging to {LOG_PATH}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("stopped", flush=True)
    finally:
        httpd.server_close()
        log_file.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the local Gundam Online patch list.")
    parser.add_argument("--client", type=Path, default=default_client())
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--point-client", action="store_true", help="rewrite BaseURL to this server")
    parser.add_argument("--restore-client", action="store_true", help="restore filelist.dat from the official backup")
    parser.add_argument("--audit", action="store_true", help="check installed files against the list")
    args = parser.parse_args()

    client = args.client.resolve()
    if not (client / "list" / "filelist.dat").is_file():
        raise SystemExit(f"client filelist not found under {client}")

    if args.restore_client:
        restore_client(client)
        if not args.audit and not args.point_client:
            return

    listing = load_filelist(client)
    print(
        f"client {client}",
        flush=True,
    )
    print(
        f"packages {len(listing.packages)} files {len(listing.files)} token {listing.token}",
        flush=True,
    )
    print(f"listed base {listing.base_url}", flush=True)

    if args.audit:
        code = audit(client, listing)
        if not args.point_client:
            raise SystemExit(code)

    if args.point_client:
        new_url = point_client(client, origin_for(args.host, args.port), listing)
        print(f"client BaseURL -> {new_url}", flush=True)
        print(f"backup {client / 'list' / 'filelist.dat.official'}", flush=True)
        listing = load_filelist(client)

    serve(client, args.host, args.port, listing)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
