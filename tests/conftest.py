"""Infraestrutura nova: HTTP efêmero e aplicação SQLite real."""

from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from experiments.sqlite_control import ControlServer


@dataclass
class Reply:
    body: bytes = b"ready"
    status: int = 200
    headers: dict = field(default_factory=dict)
    wait_headers: float = 0
    wait_body: float = 0


@pytest.fixture
def http_lab():
    resources = []

    def start(respond):
        calls = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urlsplit(self.path)
                request = SimpleNamespace(
                    path=parsed.path, query=parse_qs(parsed.query, keep_blank_values=True),
                    headers=dict(self.headers), arrived=time.monotonic(), number=len(calls) + 1,
                )
                calls.append(request)
                reply = respond(request)
                time.sleep(reply.wait_headers)
                try:
                    self.send_response(reply.status)
                    for key, value in {"Content-Type": "text/plain", **reply.headers}.items():
                        self.send_header(key, value)
                    self.send_header("Content-Length", str(len(reply.body)))
                    self.end_headers()
                    self.wfile.flush()
                    time.sleep(reply.wait_body)
                    self.wfile.write(reply.body)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()
        resources.append((server, thread))
        return SimpleNamespace(url=f"http://127.0.0.1:{server.server_port}", calls=calls)

    yield SimpleNamespace(start=start, reply=Reply)
    for server, thread in reversed(resources):
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.fixture
def sqlite_app():
    server = ControlServer(0)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    yield SimpleNamespace(server=server, url=f"http://127.0.0.1:{server.server_port}")
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
    assert not thread.is_alive()
