from unittest.mock import Mock

import pytest
import requests

from scanner.http_client import HttpClient, HttpClientError
from scanner.targets import TargetError


def test_get_preserves_http_errors_and_records_metadata(local_server):
    base, _ = local_server
    with HttpClient(interval=0) as client:
        result = client.get(base + "/error")
    assert result.status_code == 500
    assert result.size_bytes == len(result.body)
    assert len(result.body_sha256) == 64
    assert result.elapsed_ms >= 0
    assert result.request_id == 1


def test_redirect_never_leaves_original_target(local_server):
    base, state = local_server
    with HttpClient(interval=0) as client:
        result = client.get(base + "/redirect")
    assert result.status_code == 302
    assert state["requests"] == ["/redirect"]


def test_ignores_environment_proxy_and_does_not_reuse_cookies(local_server, monkeypatch):
    base, state = local_server
    monkeypatch.setenv("HTTP_PROXY", "http://192.0.2.1:9")
    monkeypatch.setenv("NO_PROXY", "")
    with HttpClient(interval=0) as client:
        client.get(base)
        client.get(base)
    assert state["cookies"] == [None, None]


def test_request_limit_prevents_extra_traffic(local_server):
    base, state = local_server
    with HttpClient(max_requests=1, interval=0) as client:
        client.get(base)
        with pytest.raises(HttpClientError) as raised:
            client.get(base)
        assert raised.value.failure.kind == "request_limit"
    assert len(state["requests"]) == 1


def test_target_is_validated_on_every_request(monkeypatch):
    with HttpClient() as client:
        send = Mock()
        monkeypatch.setattr(client._session, "get", send)
        with pytest.raises(TargetError):
            client.get("http://192.0.2.1")
        send.assert_not_called()


@pytest.mark.parametrize(("path", "limit", "kind"), [
    ("/slow", 20_000, "timeout"),
    ("/slow-body", 20_000, "timeout"),
    ("/large", 10, "response_too_large"),
])
def test_timeout_and_size_limit(local_server, path, limit, kind):
    base, _ = local_server
    with HttpClient(timeout=0.05, max_body_bytes=limit, interval=0) as client:
        with pytest.raises(HttpClientError) as raised:
            client.get(base + path)
    assert raised.value.failure.kind == kind


@pytest.mark.parametrize(("exception", "kind"), [
    (requests.ConnectionError("internal details"), "connection_error"),
    (requests.exceptions.SSLError("certificate details"), "tls_error"),
    (requests.RequestException("internal details"), "http_error"),
])
def test_transport_errors_are_structured(monkeypatch, exception, kind):
    with HttpClient() as client:
        monkeypatch.setattr(client._session, "get", Mock(side_effect=exception))
        with pytest.raises(HttpClientError) as raised:
            client.get("http://127.0.0.1:1")
    assert raised.value.failure.kind == kind
    assert "details" not in raised.value.failure.message


def test_interval_is_enforced(local_server, monkeypatch):
    base, _ = local_server
    sleeps = []
    monkeypatch.setattr("scanner.http_client.time.sleep", sleeps.append)
    with HttpClient(interval=1) as client:
        client.get(base)
        client.get(base)
    assert len(sleeps) == 1
    assert 0 < sleeps[0] <= 1


@pytest.mark.parametrize("settings", [
    {"timeout": 0}, {"timeout": float("nan")}, {"interval": -1},
    {"interval": float("inf")}, {"max_requests": 0}, {"max_body_bytes": 0},
])
def test_reject_invalid_limits(settings):
    with pytest.raises(ValueError):
        HttpClient(**settings)
