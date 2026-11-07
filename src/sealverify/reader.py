"""仅在回环地址提供阅读器资源；不提供目录浏览或任意文件接口。"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from io import BytesIO
import json
from pathlib import Path
import secrets
import threading
from typing import Optional
from urllib.parse import urlsplit
import webbrowser
from zipfile import BadZipFile, ZipFile


MAX_FILE_BYTES = 256 * 1024 * 1024
WEB_ROOT = files("sealverify").joinpath("web")
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".otf": "font/otf",
    ".txt": "text/plain; charset=utf-8", ".ofd": "application/ofd",
}


def read_document(path: Path) -> bytes:
    """读取明确指定的文件，大小受限；不解压到磁盘、不修改原件。"""
    if path.suffix.lower() != ".ofd":
        raise ValueError("请选择 .ofd 文件。")
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("OFD 文件超过 256 MiB 的阅读上限。")
    try:
        with ZipFile(BytesIO(data)) as archive:
            if "OFD.xml" not in archive.namelist():
                raise ValueError("文件缺少 OFD.xml，无法作为 OFD 打开。")
    except BadZipFile as exc:
        raise ValueError("文件不是有效的 OFD/ZIP 容器，可能已经损坏。") from exc
    return data


class ReaderServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int = 0, document: Optional[bytes] = None,
                 name: Optional[str] = None):
        self.token = secrets.token_urlsafe(32)
        self.document = document
        self.document_name = name
        super().__init__(("127.0.0.1", port), ReaderHandler)
        self.authority = "127.0.0.1:" + str(self.server_port)
        self.url = "http://" + self.authority + "/" + self.token + "/"


class ReaderHandler(BaseHTTPRequestHandler):
    server_version = "SealVerifyReader"
    sys_version = ""

    def log_message(self, format, *args):
        # 避免记录文件名、访问令牌和文档内容。
        pass

    def _send(self, status, body=b"", content_type="text/plain; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", (
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' blob: data:; font-src 'self' blob: data:; "
            "connect-src 'self' blob:; worker-src 'self' blob:; "
            "frame-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        ))
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

    def _resource(self):
        if self.headers.get("Host") != self.server.authority:
            self._send(403)
            return None
        origin = self.headers.get("Origin")
        if origin and origin != "http://" + self.server.authority:
            self._send(403)
            return None
        prefix = "/" + self.server.token + "/"
        path = urlsplit(self.path).path
        if not path.startswith(prefix):
            self._send(404)
            return None
        return path[len(prefix):]

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        resource = self._resource()
        if resource is None:
            return
        if resource == "session.json":
            payload = {"name": self.server.document_name,
                       "hasDocument": self.server.document is not None}
            self._send(200, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")
        elif resource == "document.ofd" and self.server.document is not None:
            self._send(200, self.server.document, "application/ofd")
        else:
            # 精确允许列表；URL 的任何部分都不参与文件系统路径拼接。
            allowed = {
                "": "index.html", "reader.js": "reader.js", "reader.css": "reader.css",
                "vendor/viewer.css": "vendor/viewer.css",
                "vendor/THIRD_PARTY_NOTICES.txt": "vendor/THIRD_PARTY_NOTICES.txt",
                "fonts/NotoSansCJKsc-Regular.otf": "fonts/NotoSansCJKsc-Regular.otf",
                "fonts/OFL.txt": "fonts/OFL.txt", "demo.ofd": "demo.ofd",
            }
            asset = allowed.get(resource)
            if asset is None:
                self._send(404)
                return
            try:
                data = WEB_ROOT.joinpath(*asset.split("/")).read_bytes()
            except OSError:
                self._send(500, "阅读资源缺失，请重新安装 SealVerify。".encode("utf-8"))
                return
            self._send(200, data, CONTENT_TYPES[Path(asset).suffix])

    def do_POST(self):
        resource = self._resource()
        if resource is None:
            return
        if resource == "inspect":
            # 此接口只处理用户所选的字节，不接受路径，也不保存文件。
            if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1:
                self._send(411)
                return
            try:
                size = int(self.headers['Content-Length'])
            except ValueError:
                self._send(400)
                return
            if not 0 <= size <= MAX_FILE_BYTES:
                self._send(413)
                return
            if self.headers.get_content_type() not in ('application/ofd', 'application/octet-stream'):
                self._send(415)
                return
            self.connection.settimeout(30)
            try:
                data = self.rfile.read(size)
                if len(data) != size:
                    self._send(400)
                    return
                from .inspection import inspect_ofd
                payload = json.dumps(inspect_ofd(data), ensure_ascii=False).encode('utf-8')
                if len(payload) > 32 * 1024 * 1024:
                    self._send(422, '解析清单超过 32 MiB 展示上限。'.encode('utf-8'))
                    return
                self._send(200, payload, 'application/json; charset=utf-8')
            except (TimeoutError, ConnectionError):
                self._send(408)
            return
        if resource != "shutdown":
            self._send(405)
            return
        self._send(200, b"closed")
        threading.Thread(target=self.server.shutdown, daemon=True).start()


def serve(path: Optional[Path] = None, *, port: int = 0,
          open_browser: bool = True, demo: bool = False) -> int:
    document = read_document(path) if path is not None else None
    name = path.name if path is not None else None
    if demo:
        document, name = WEB_ROOT.joinpath("demo.ofd").read_bytes(), "阅读示例.ofd"
    with ReaderServer(port, document, name) as server:
        print("SealVerify OFD 阅读器：" + server.url, flush=True)
        print("文件仅在本机读取。使用页面中的“退出阅读器”或 Ctrl+C 结束。", flush=True)
        if open_browser:
            try:
                opened = webbrowser.open(server.url)
            except webbrowser.Error:
                opened = False
            if not opened:
                print("未能自动打开浏览器，请复制上方地址到 Chrome 或 Edge。", flush=True)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass
    return 0
