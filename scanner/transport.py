"""Transporte Requests e supervisão de um worker com IPC JSON limitado."""
import base64
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

import requests
from urllib3.exceptions import ReadTimeoutError, HTTPError, DecodeError, ProtocolError

from scanner import __version__
from scanner.targets import validate_target

FRAME_LIMIT = 65536


class TransportError(Exception):
    def __init__(self, kind):
        self.kind = kind
        super().__init__(kind)


def session():
    result = requests.Session()
    result.trust_env = False
    result.headers.update({'User-Agent': f'WebVulnScanner/{__version__}'})
    return result


def collect(connection, target, timeout, max_body_bytes, remaining, emit):
    """Mesmo caminho de HTTP no worker e no transporte injetável de testes."""
    target = validate_target(target)
    try:
        connection.cookies.clear()
        with connection.get(target, timeout=timeout, allow_redirects=False, stream=True) as response:
            size = 0
            # read1 devolve blocos disponíveis sem esperar completar 8192 bytes.
            # Assim também contabilizamos progresso de corpos lentos antes do kill.
            while True:
                chunk_size = min(8192, remaining - size + 1, max_body_bytes - size + 1)
                chunk = response.raw.read1(chunk_size, decode_content=True)
                if not chunk:
                    break
                emit({'chunk': base64.b64encode(chunk).decode('ascii')})
                size += len(chunk)
                if size > remaining:
                    raise TransportError('total_body_limit')
                if size > max_body_bytes:
                    raise TransportError('response_too_large')
            result = dict(url=response.url, status_code=response.status_code,
                          content_type=response.headers.get('Content-Type', ''),
                          security_headers={name: response.headers[name] for name in (
                              'Content-Security-Policy', 'Content-Security-Policy-Report-Only',
                              'X-Content-Type-Options', 'Content-Disposition') if name in response.headers})
            if len(json.dumps(result).encode('utf-8')) > FRAME_LIMIT // 2:
                raise TransportError('metadata_limit')
            emit({'result': result})
    except (requests.Timeout, ReadTimeoutError):
        raise TransportError('timeout') from None
    except requests.exceptions.SSLError:
        raise TransportError('tls_error') from None
    except requests.ConnectionError as error:
        raise TransportError('timeout' if any(isinstance(arg, ReadTimeoutError) for arg in error.args) else 'connection_error') from None
    except requests.RequestException:
        raise TransportError('http_error') from None
    except (DecodeError, ProtocolError, HTTPError):
        raise TransportError('http_error') from None


class InlineTransport:
    """Injeção explícita para testes de falha; não possui garantia de deadline."""
    def __init__(self):
        self.connection = session()

    def prepare(self):
        pass

    def request(self, command, deadline, consume):
        result, body = {}, bytearray()
        def emit(frame):
            if 'chunk' in frame:
                chunk = base64.b64decode(frame['chunk'], validate=True)
                consume(len(chunk))
                body.extend(chunk)
            else:
                result.update(frame['result'])
        collect(self.connection, **command, emit=emit)
        return result, bytes(body)

    def close(self):
        self.connection.close()


class ProcessTransport:
    def __init__(self):
        self.process = None
        self.reader = None
        self._stop = threading.Event()
        self._frames = queue.Queue(maxsize=2)

    def prepare(self):
        if self.process is not None:
            return
        try:
            self._start()
            if self._frames.get(timeout=10) != {'ready': True}:
                raise TransportError('transport_error')
        except (KeyboardInterrupt, Exception):
            self.close()
            raise

    def _start(self):
        self._stop.clear()
        self._frames = queue.Queue(maxsize=2)
        self.process = subprocess.Popen(
            [sys.executable, '-B', '-u', str(Path(__file__).with_name('transport_worker.py'))],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            cwd=str(Path(__file__).resolve().parent.parent),
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0,
        )
        stream = self.process.stdout
        def read():
            try:
                while not self._stop.is_set():
                    line = stream.readline(FRAME_LIMIT + 1)
                    if not line or len(line) > FRAME_LIMIT or not line.endswith(b'\n'):
                        frame = {'error': 'transport_error'}
                    else:
                        frame = json.loads(line)
                    while not self._stop.is_set():
                        try:
                            self._frames.put(frame, timeout=0.05)
                            break
                        except queue.Full:
                            pass
                    if not line:
                        break
            except (OSError, ValueError):
                if not self._stop.is_set():
                    try:
                        self._frames.put({'error': 'transport_error'}, timeout=0.05)
                    except queue.Full:
                        pass
        self.reader = threading.Thread(target=read, name='probekit-transport-reader', daemon=True)
        self.reader.start()

    def request(self, command, deadline, consume):
        self.prepare()
        end = time.monotonic() + deadline
        encoded = (json.dumps(command) + '\n').encode('utf-8')
        if len(encoded) > FRAME_LIMIT:
            raise TransportError('metadata_limit')
        body = bytearray()
        try:
            # A single bounded command, well below pipe capacity in supported
            # configuration. A separate writer also covers a wedged worker.
            input_stream = self.process.stdin
            def send():
                try:
                    input_stream.write(encoded)
                    input_stream.flush()
                except (OSError, ValueError):
                    pass
            writer = threading.Thread(target=send, name='probekit-transport-writer', daemon=True)
            writer.start()
            while True:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise TransportError('deadline_exceeded')
                try:
                    frame = self._frames.get(timeout=min(remaining, 0.05))
                except queue.Empty:
                    continue
                if 'error' in frame:
                    if frame['error'] in {'transport_error', 'execution_error'}:
                        raise RuntimeError('Falha inesperada no transporte isolado.')
                    raise TransportError(frame['error'])
                if 'chunk' in frame:
                    chunk = base64.b64decode(frame['chunk'], validate=True)
                    consume(len(chunk))
                    if len(body) + len(chunk) <= min(command['max_body_bytes'], command['remaining']):
                        body.extend(chunk)
                    continue
                writer.join(timeout=1)
                return frame['result'], bytes(body)
        except (KeyboardInterrupt, Exception) as error:
            try:
                self._abort(consume)
            finally:
                if isinstance(error, KeyboardInterrupt) or not isinstance(error, TransportError) or error.kind == 'deadline_exceeded':
                    # Um bloco pode estar em leitura ou parcialmente escrito no IPC.
                    # Reserva conservadora impede contornar o teto após cancelamento.
                    consume(min(8192, command['max_body_bytes'] + 1, command['remaining'] + 1), reserved=True)
                if 'writer' in locals():
                    writer.join(timeout=1)
            raise

    def _abort(self, consume):
        try:
            if self.process is not None and self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=5)
            end = time.monotonic() + 1
            while time.monotonic() < end:
                try:
                    frame = self._frames.get(timeout=0.02)
                except queue.Empty:
                    if self.reader is None or not self.reader.is_alive():
                        break
                    continue
                if 'chunk' in frame:
                    consume(len(base64.b64decode(frame['chunk'], validate=True)))
        finally:
            self.close()

    def close(self):
        self._stop.set()
        process, self.process = self.process, None
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            for stream in (process.stdin, process.stdout):
                stream.close()
        if self.reader is not None:
            self.reader.join(timeout=5)
            if self.reader.is_alive():
                raise OSError('Leitor do transporte não foi encerrado.')
            self.reader = None
