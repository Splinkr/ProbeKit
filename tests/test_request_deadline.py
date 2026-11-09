from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
import pytest

from scanner.http_client import HttpClient, HttpClientError


@pytest.mark.parametrize('phase', ['headers', 'body'])
def test_continuous_trickle_hits_total_deadline_and_worker_is_gone(phase):
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(self.path)
            try:
                if phase == 'headers':
                    self.wfile.write(b'HTTP/1.1 200 OK\r\nX-Trickle: ')
                else:
                    self.send_response(200)
                    self.send_header('Content-Length', '1000')
                    self.end_headers()
                for _ in range(1000):
                    self.wfile.write(b'x')
                    self.wfile.flush()
                    time.sleep(0.01)
            except (OSError, ConnectionError):
                pass
        def log_message(self, *_args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with HttpClient(timeout=2, request_deadline=0.5, interval=0) as client:
            started = time.monotonic()
            with pytest.raises(HttpClientError) as error:
                client.get(f'http://127.0.0.1:{server.server_port}/')
            assert error.value.failure.kind == 'deadline_exceeded'
            assert time.monotonic() - started < 2
            assert client.request_count == len(calls) == 1
            assert client._transport.process is None
            assert client._transport.reader is None
            if phase == 'body':
                assert client.resources.body_bytes_observed > 0
            assert client.resources.body_bytes_reserved > 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_deadline_has_no_retry_and_next_request_uses_new_worker(http_lab):
    site = http_lab.start(lambda request: http_lab.reply(wait_headers=0.7 if request.path == '/slow' else 0))
    with HttpClient(timeout=2, request_deadline=0.15, interval=0) as client:
        with pytest.raises(HttpClientError) as error:
            client.get(site.url + '/slow')
        assert error.value.failure.kind == 'deadline_exceeded'
        assert client._transport.process is None
        assert client.get(site.url + '/fast').request_id == 2
        assert len(site.calls) == 2
    time.sleep(0.1)
    assert [call.path for call in site.calls] == ['/slow', '/fast']


def test_cancel_supervisor_closes_process_and_reader(http_lab, monkeypatch):
    site = http_lab.start(lambda _: http_lab.reply(wait_headers=0.3))
    with HttpClient(interval=0) as client:
        client._transport.prepare()
        process, reader = client._transport.process, client._transport.reader
        def interrupt(*_args, **_options):
            raise KeyboardInterrupt
        monkeypatch.setattr(client._transport._frames, 'get', interrupt)
        with pytest.raises(KeyboardInterrupt):
            client.get(site.url)
        assert process.poll() is not None
        assert not reader.is_alive()
        assert client.request_count == 1


def test_compressed_stream_limit_and_deadline_preserve_decompression(http_lab):
    import gzip
    site = http_lab.start(lambda _: http_lab.reply(body=gzip.compress(b'x' * 10000), headers={'Content-Encoding': 'gzip'}))
    with HttpClient(max_total_body_bytes=100, interval=0) as client:
        from scanner.resources import ResourceLimit
        with pytest.raises(ResourceLimit) as error:
            client.get(site.url)
        assert error.value.reason == 'max_total_body_bytes'
        assert client.resources.total_body_bytes == 101
