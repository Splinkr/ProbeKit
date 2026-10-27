"""HTTP real e limites, independentemente do detector."""

from datetime import datetime
import gzip
import hashlib
from unittest.mock import Mock

import pytest
import requests

from scanner.http_client import HttpClient, HttpClientError


@pytest.mark.parametrize("status", [200, 204, 302, 404, 500])
def test_status_is_evidence_not_a_transport_exception(http_lab, status):
    body = b"" if status == 204 else b"response"
    origin = http_lab.start(lambda _: http_lab.reply(status=status, body=body))
    with HttpClient() as client:
        evidence = client.get(origin.url)
    assert evidence.status_code == status
    assert evidence.body == body
    assert evidence.size_bytes == len(body)
    assert evidence.body_sha256 == hashlib.sha256(body).hexdigest()
    assert datetime.fromisoformat(evidence.collected_at).utcoffset().total_seconds() == 0
    assert evidence.elapsed_ms >= 0
    assert len(origin.calls) == 1


def test_redirect_is_not_followed_even_to_a_second_local_server(http_lab):
    sink = http_lab.start(lambda _: http_lab.reply())
    redirect = http_lab.start(lambda _: http_lab.reply(status=302, headers={"Location": sink.url}))
    with HttpClient() as client:
        assert client.get(redirect.url).status_code == 302
    assert sink.calls == []


def test_references_have_no_cookie_or_proxy_inheritance(http_lab, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://192.0.2.5:9")
    monkeypatch.setenv("NO_PROXY", "")
    origin = http_lab.start(lambda _: http_lab.reply(headers={"Set-Cookie": "auth=private-token"}))
    with HttpClient(interval=0) as client:
        first = client.get(origin.url)
        second = client.get(origin.url)
    assert (first.request_id, second.request_id) == (1, 2)
    assert all("Cookie" not in call.headers for call in origin.calls)
    assert all("Authorization" not in call.headers for call in origin.calls)


@pytest.mark.parametrize("delay_field", ["wait_headers", "wait_body"])
def test_timeout_applies_before_headers_and_during_streaming(http_lab, delay_field):
    origin = http_lab.start(lambda _: http_lab.reply(**{delay_field: 0.3}))
    with HttpClient(timeout=0.05) as client, pytest.raises(HttpClientError) as failure:
        client.get(origin.url)
    assert failure.value.failure.kind == "timeout"
    assert failure.value.failure.request_id == 1


def test_body_limit_is_measured_after_decompression(http_lab):
    compressed = gzip.compress(b"z" * 20_000)
    origin = http_lab.start(lambda _: http_lab.reply(body=compressed, headers={"Content-Encoding": "gzip"}))
    with HttpClient(max_body_bytes=100) as client, pytest.raises(HttpClientError) as failure:
        client.get(origin.url)
    assert failure.value.failure.kind == "response_too_large"


def test_budget_blocks_the_next_get_before_sending_it(http_lab):
    origin = http_lab.start(lambda _: http_lab.reply())
    with HttpClient(max_requests=2, interval=0) as client:
        client.get(origin.url)
        client.get(origin.url)
        with pytest.raises(HttpClientError) as failure:
            client.get(origin.url)
        assert client.request_count == 2
    assert failure.value.failure.kind == "request_limit"
    assert len(origin.calls) == 2


def test_minimum_interval_is_observable_between_request_starts(http_lab):
    origin = http_lab.start(lambda _: http_lab.reply())
    with HttpClient(interval=0.1) as client:
        client.get(origin.url)
        client.get(origin.url)
    assert origin.calls[1].arrived - origin.calls[0].arrived >= 0.08


@pytest.mark.parametrize("exception,kind", [
    (requests.exceptions.SSLError("secret details"), "tls_error"),
    (requests.ConnectionError("secret details"), "connection_error"),
    (requests.RequestException("secret details"), "http_error"),
])
def test_exception_details_do_not_leak_into_failures(monkeypatch, exception, kind):
    monkeypatch.setattr("requests.Session.get", Mock(side_effect=exception))
    with HttpClient() as client, pytest.raises(HttpClientError) as failure:
        client.get("http://127.0.0.1:1")
    assert failure.value.failure.kind == kind
    assert "secret" not in failure.value.failure.message


@pytest.mark.parametrize("options", [
    {"timeout": 0}, {"timeout": float("nan")}, {"timeout": float("inf")},
    {"interval": -0.1}, {"interval": float("nan")},
    {"max_requests": 0}, {"max_body_bytes": 0},
])
def test_invalid_transport_limits_are_rejected(options):
    with pytest.raises(ValueError):
        HttpClient(**options)
