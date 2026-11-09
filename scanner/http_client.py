"""Cliente GET local: orçamento global e prazo supervisionado por processo."""
import hashlib
import math
import time
from scanner.models import RequestFailure, ResponseEvidence, utc_now
from scanner.resources import Resources, ResourceLimit
from scanner.targets import validate_target
from scanner.transport import ProcessTransport, TransportError

class HttpClientError(Exception):
    def __init__(self, failure):
        self.failure = failure
        super().__init__(failure.message)

class HttpClient:
    transport_factory = ProcessTransport

    def __init__(self, timeout=5.0, max_requests=10, interval=0.2, max_body_bytes=1_048_576,
                 request_deadline=15.0, **resource_options):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('O timeout deve ser positivo e finito.')
        if not math.isfinite(interval) or interval < 0:
            raise ValueError('O intervalo deve ser não negativo e finito.')
        if not math.isfinite(request_deadline) or request_deadline <= 0:
            raise ValueError('O prazo HTTP deve ser positivo e finito.')
        if max_requests < 1 or max_body_bytes < 1:
            raise ValueError('Os limites de requisições e bytes devem ser positivos.')
        self.resources = Resources(**resource_options)
        self.timeout, self.max_requests, self.interval = timeout, max_requests, interval
        self.max_body_bytes, self.request_deadline = max_body_bytes, request_deadline
        self.request_count = 0
        self._last_request_at = None
        self._transport = self.transport_factory()

    def get(self, url):
        target = validate_target(url)
        if self.request_count >= self.max_requests:
            raise HttpClientError(RequestFailure(self.request_count + 1, target, 'request_limit', 'Limite de requisições atingido.'))
        if not self.resources.url(target):
            raise ResourceLimit(self.resources.stop_reasons[-1])
        # Reserva conservadora de metadados por GET, incluindo sonda,
        # comparação e ledger; bytes de corpo têm teto independente.
        self.resources.require({'url': target, 'failure_url_reservation': target, 'request_id': self.request_count + 1, 'reservation': 'x' * 4096})
        remaining = self.resources.limits['max_total_body_bytes'] - self.resources.total_body_bytes
        if remaining <= 0:
            self.resources.reject('max_total_body_bytes')
            raise ResourceLimit('max_total_body_bytes')
        self._transport.prepare()
        if self._last_request_at is not None:
            time.sleep(max(0, self.interval - (time.monotonic() - self._last_request_at)))
        self.request_count += 1
        started = time.monotonic()
        self._last_request_at = started
        collected_at = utc_now()
        def consume(size, *, reserved=False):
            if reserved:
                size = min(size, max(0, self.resources.limits['max_total_body_bytes'] - self.resources.total_body_bytes))
                self.resources.body_bytes_reserved += size
            else:
                self.resources.body_bytes_observed += size
            self.resources.total_body_bytes += size
        try:
            metadata, content = self._transport.request(dict(target=target, timeout=self.timeout,
                max_body_bytes=self.max_body_bytes, remaining=remaining), self.request_deadline, consume)
            self.resources.require(metadata)
            return ResponseEvidence(request_id=self.request_count, collected_at=collected_at,
                size_bytes=len(content), body_sha256=hashlib.sha256(content).hexdigest(),
                elapsed_ms=round((time.monotonic() - started) * 1000, 3), body=content, **metadata)
        except TransportError as error:
            if error.kind in {'total_body_limit', 'metadata_limit'}:
                reason = 'max_total_body_bytes' if error.kind == 'total_body_limit' else 'max_metadata_bytes'
                self.resources.reject(reason)
                raise ResourceLimit(reason) from None
            messages = dict(timeout='Tempo limite de conexão ou leitura excedido.',
                deadline_exceeded='Prazo total da requisição excedido.',
                tls_error='Falha na verificação do certificado TLS.',
                connection_error='Não foi possível conectar ao alvo local.',
                response_too_large='Resposta excedeu o limite de bytes.',
                http_error='Falha ao receber a resposta HTTP.', transport_error='Falha no processo de transporte.')
            kind = error.kind if error.kind in messages else 'transport_error'
            raise HttpClientError(RequestFailure(self.request_count, target, kind, messages[kind])) from None

    def close(self):
        self._transport.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
