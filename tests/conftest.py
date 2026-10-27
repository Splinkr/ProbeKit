from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time

import pytest


@pytest.fixture
def local_server():
    state = {"requests": [], "cookies": []}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["requests"].append(self.path)
            state["cookies"].append(self.headers.get("Cookie"))
            body = b"reference body"
            status = 200
            content_type = "text/plain; charset=utf-8"
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "http://example.invalid/never-follow")
                self.end_headers()
                return
            if self.path == "/slow":
                time.sleep(0.25)
            if self.path == "/slow-body":
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.flush()
                time.sleep(0.25)
                try:
                    self.wfile.write(b"ok")
                except OSError:
                    pass
                return
            if self.path == "/large":
                body = b"X" * 20_000
            if self.path == "/changing":
                body = f"request {len(state['requests'])}".encode()
            if self.path == "/error":
                status = 500
            if self.path == "/json":
                content_type = "application/json"
                body = b'{"ok": true}'
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "session=do-not-persist")
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", state
    server.shutdown()
    server.server_close()
    thread.join()
