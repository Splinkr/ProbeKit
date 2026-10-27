"""O escopo deve ser decidido antes de qualquer tráfego."""

from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest

from scanner.http_client import HttpClient
from scanner.modules.sqli import build_probe_plan, probe_url
from scanner.targets import TargetError, validate_target


@pytest.mark.parametrize("source,canonical", [
    ("http://localhost:3000", "http://127.0.0.1:3000/"),
    ("https://LOCALHOST:443/search?q=apple", "https://127.0.0.1:443/search?q=apple"),
    ("http://127.2.3.4:8080/a", "http://127.2.3.4:8080/a"),
    ("https://[::1]/", "https://[::1]/"),
])
def test_canonical_local_origins(source, canonical):
    assert validate_target(source) == canonical
    assert validate_target(canonical) == canonical


@pytest.mark.parametrize("destination", [
    "http://8.8.8.8", "http://10.0.0.1", "http://172.16.0.1", "http://192.168.0.1",
    "http://169.254.169.254", "http://0.0.0.0", "http://[::]", "http://example.org",
    "http://localhost.example.org", "http://127.0.0.1.nip.io", "http://2130706433",
    "http://127.1", "http://0x7f000001", "http://user:secret@localhost",
    "http://localhost@8.8.8.8", "http://%6cocalhost", "http://[::1%25zone]",
    "http://localhost:0", "http://localhost:65536", "http://[::1",
    "file:///C:/secret.txt", "localhost:3000", "http://localhost/#section",
    "http://localhost/\r\nHost:example.org", "http://localhost\\@example.org",
])
def test_rejected_destinations_never_reach_transport(destination, monkeypatch):
    send = Mock()
    monkeypatch.setattr("requests.Session.get", send)
    with HttpClient() as client, pytest.raises(TargetError):
        client.get(destination)
    send.assert_not_called()


@pytest.mark.parametrize("path", ["/rest/products/search", "/control/vulnerable/search", "/control/safe/search"])
def test_supported_paths_share_the_same_read_only_plan(path):
    url = "http://127.0.0.1:8001" + path + "?lang=pt&q=apple&lang=en&empty="
    plan = build_probe_plan(url, samples=2, max_requests=10)
    assert len(plan) == 10
    assert [step.request_id for step in plan] == list(range(1, 11))
    assert plan[0].input_value == plan[1].input_value == plan[-1].input_value == "apple"
    for step in plan:
        query = parse_qs(urlsplit(probe_url(url, step.input_value)).query, keep_blank_values=True)
        assert query == {"lang": ["pt", "en"], "q": [step.input_value], "empty": [""]}
        assert not any(word in step.input_value.upper() for word in ("UNION", "DELETE", "UPDATE", ";"))


@pytest.mark.parametrize("suffix,samples,budget", [
    ("/", 2, 10), ("/rest/products/search", 2, 10),
    ("/rest/products/search?q=", 2, 10), ("/rest/products/search?q=a&q=b", 2, 10),
    ("/rest/products/search?q=apple%27", 2, 10),
    ("/rest/products/search?q=apple", 1, 10),
    ("/rest/products/search?q=apple", 2, 9),
    ("/rest/products/search?q=apple", 3, 10),
])
def test_sql_plan_refuses_invalid_input_or_insufficient_budget(suffix, samples, budget):
    with pytest.raises(ValueError):
        build_probe_plan("http://localhost:3000" + suffix, samples, budget)
