"""Cliente GET local com limites explícitos e sem redirecionamento automático."""

import hashlib
import math
import time

import requests

from scanner import __version__
from scanner.models import RequestFailure, ResponseEvidence, utc_now
from scanner.targets import validate_target


class HttpClientError(Exception):
    def __init__(self, failure: RequestFailure):
        self.failure = failure
        super().__init__(failure.message)


class HttpClient:
    def __init__(
        self,
        timeout: float = 5.0,
        max_requests: int = 10,
        interval: float = 0.2,
        max_body_bytes: int = 1_048_576,
    ):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("O timeout deve ser positivo e finito.")
        if not math.isfinite(interval) or interval < 0:
            raise ValueError("O intervalo deve ser não negativo e finito.")
        if max_requests < 1 or max_body_bytes < 1:
            raise ValueError("Os limites de requisições e bytes devem ser positivos.")
        self.timeout = timeout
        self.max_requests = max_requests
        self.interval = interval
        self.max_body_bytes = max_body_bytes
        self.request_count = 0
        self._last_request_at: float | None = None
        self._session = requests.Session()
        self._session.trust_env = False
        self._session.headers.update({"User-Agent": f"WebVulnScanner/{__version__}"})

    def get(self, url: str) -> ResponseEvidence:
        target = validate_target(url)
        if self.request_count >= self.max_requests:
            raise HttpClientError(RequestFailure(
                self.request_count + 1, target, "request_limit", "Limite de requisições atingido."
            ))
        if self._last_request_at is not None:
            time.sleep(max(0, self.interval - (time.monotonic() - self._last_request_at)))
        self.request_count += 1
        request_id = self.request_count
        started = time.monotonic()
        self._last_request_at = started
        collected_at = utc_now()
        try:
            # Cada referência começa sem cookies de respostas anteriores.
            self._session.cookies.clear()
            with self._session.get(
                target, timeout=self.timeout, allow_redirects=False, stream=True
            ) as response:
                body = bytearray()
                for chunk in response.iter_content(chunk_size=8192):
                    if len(body) + len(chunk) > self.max_body_bytes:
                        raise HttpClientError(RequestFailure(
                            request_id, target, "response_too_large",
                            f"Resposta excedeu o limite de {self.max_body_bytes} bytes."
                        ))
                    body.extend(chunk)
                content = bytes(body)
                return ResponseEvidence(
                    request_id=request_id,
                    url=response.url,
                    collected_at=collected_at,
                    status_code=response.status_code,
                    content_type=response.headers.get("Content-Type", ""),
                    size_bytes=len(content),
                    body_sha256=hashlib.sha256(content).hexdigest(),
                    elapsed_ms=round((time.monotonic() - started) * 1000, 3),
                    body=content,
                )
        except requests.Timeout as error:
            raise HttpClientError(RequestFailure(
                request_id, target, "timeout", "Tempo limite de conexão ou leitura excedido."
            )) from error
        except requests.exceptions.SSLError as error:
            raise HttpClientError(RequestFailure(
                request_id, target, "tls_error", "Falha na verificação do certificado TLS."
            )) from error
        except requests.ConnectionError as error:
            # Requests pode encapsular timeout durante streaming como ConnectionError.
            from urllib3.exceptions import ReadTimeoutError

            is_timeout = any(isinstance(argument, ReadTimeoutError) for argument in error.args)
            kind = "timeout" if is_timeout else "connection_error"
            message = "Tempo limite de leitura excedido." if is_timeout else "Não foi possível conectar ao alvo local."
            raise HttpClientError(RequestFailure(request_id, target, kind, message)) from error
        except requests.RequestException as error:
            raise HttpClientError(RequestFailure(
                request_id, target, "http_error", "Falha ao receber a resposta HTTP."
            )) from error

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
