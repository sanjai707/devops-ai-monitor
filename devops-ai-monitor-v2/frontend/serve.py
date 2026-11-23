import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


BACKEND_API_URL = os.getenv("BACKEND_API_URL", "http://127.0.0.1:8000").rstrip("/")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "dist")
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def do_GET(self):
        if self._is_api_request():
            self._proxy_api_request()
            return
        if self._static_file_exists():
            super().do_GET()
            return
        self.path = "/index.html"
        super().do_GET()

    def do_POST(self):
        if self._is_api_request():
            self._proxy_api_request()
            return
        self.send_error(404)

    def do_PUT(self):
        if self._is_api_request():
            self._proxy_api_request()
            return
        self.send_error(404)

    def _is_api_request(self):
        return urlsplit(self.path).path == "/api" or urlsplit(self.path).path.startswith("/api/")

    def _static_file_exists(self):
        requested = urlsplit(self.path).path.lstrip("/")
        candidate = os.path.realpath(os.path.join(STATIC_DIR, requested))
        static_root = os.path.realpath(STATIC_DIR)
        return candidate.startswith(static_root + os.sep) and os.path.isfile(candidate)

    def _proxy_api_request(self):
        parsed = urlsplit(self.path)
        api_path = parsed.path[4:] or "/"
        target_url = f"{BACKEND_API_URL}{api_path}"
        if parsed.query:
            target_url = f"{target_url}?{parsed.query}"

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length) if content_length else None
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP_HEADERS
            and key.lower() not in {"host", "content-length"}
        }
        request = Request(target_url, data=body, headers=headers, method=self.command)

        try:
            with urlopen(request, timeout=190) as response:
                self._send_upstream_response(response.status, response.headers, response.read())
        except HTTPError as response:
            self._send_upstream_response(response.code, response.headers, response.read())
        except (URLError, TimeoutError) as error:
            message = f'{{"detail":"Backend API unavailable: {type(error).__name__}"}}'.encode()
            self._send_upstream_response(502, {"Content-Type": "application/json"}, message)

    def _send_upstream_response(self, status, headers, body):
        self.send_response(status)
        for key, value in headers.items():
            if key.lower() not in HOP_BY_HOP_HEADERS and key.lower() not in {
                "content-length",
                "content-encoding",
            }:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *args):
        super().log_message(format_string, *args)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 3000), DashboardHandler)
    print(f"Dashboard serving on 0.0.0.0:3000; API proxy target: {BACKEND_API_URL}")
    server.serve_forever()
