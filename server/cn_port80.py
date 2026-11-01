"""Port 80 stand-in for the hostnames baked into the China client.

The launcher restores patcher.exe and the news page on every update check,
so those files keep the original URLs:

    http://ms.patch1.9you.com/ms_patch.ini
    http://ms.9you.com/html/launcherv2/

Point those names at 127.0.0.1 in the hosts file. This process answers
them. The patch body still sends file downloads to the server on port 8766.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INI = '"138""http://127.0.0.1:8766/patch_files/release/""138#sysinfo.ini"\r\n'.encode("ascii")
PAGE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>敢达</title>
<style>
body { margin: 0; background: #1b2430; color: #e8eef5; font-family: "Microsoft YaHei", sans-serif; }
main { padding: 48px 56px; }
h1 { font-size: 22px; font-weight: 600; margin: 0 0 12px; }
p { margin: 0; line-height: 1.7; color: #c5d0dc; }
</style>
</head>
<body>
<main>
<h1>本地公告</h1>
<p>原来的公告页已经换成这一页。点启动器右侧的开始按钮进入游戏。</p>
</main>
</body>
</html>
""".encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "cn-port80"

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in ("/ms_patch.ini", "/ms_patch_classic.ini"):
            body, kind = INI, "text/plain; charset=ascii"
        elif path.startswith("/html/"):
            body, kind = PAGE, "text/html; charset=utf-8"
        else:
            body, kind = b"not found\n", "text/plain"
            self._send(404, kind, body)
            return
        self._send(200, kind, body)

    def _send(self, code: int, kind: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    httpd = ThreadingHTTPServer(("127.0.0.1", 80), Handler)
    print("http://127.0.0.1:80/", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
