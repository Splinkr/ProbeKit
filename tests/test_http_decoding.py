"""Decodificação de respostas não confiáveis, sem mudar os critérios dos módulos."""

from dataclasses import replace
import hashlib

import pytest

from scanner.discovery import discover
from scanner.exposure_analysis import observe as observe_exposure
from scanner.models import ResponseEvidence, XssProbeEvidence, utc_now
from scanner.sqli_features import extract_features
from scanner.xss_analysis import inspect_response


CASES = [
    ("", b"caf\xc3\xa9", "café"),
    ("utf-8", "café".encode(), "café"),
    ("iso-8859-1", b"caf\xe9", "café"),
    ("windows-1252", b"price \x80", "price €"),
    ("unknown-probekit-charset", b"caf\xc3\xa9", "café"),
    ("idna", b"caf\xc3\xa9", "café"),
    ("base64_codec", b"caf\xc3\xa9", "café"),
    ("utf-8", b"bad\xff", "bad\ufffd"),
]


def evidence(body, content_type):
    return ResponseEvidence(1, "http://127.0.0.1/", utc_now(), 200, content_type,
                            len(body), hashlib.sha256(body).hexdigest(), 0, body)


@pytest.mark.parametrize("charset,body,expected", CASES)
def test_http_body_decoding_preserves_valid_encodings_and_falls_back(charset, body, expected):
    from scanner.decoding import decode_http_body

    media = "text/plain" + ("; charset=" + charset if charset else "")
    assert decode_http_body(body, media) == expected


@pytest.mark.parametrize("charset", ["utf-8", "iso-8859-1", "windows-1252", "unknown-probekit-charset", "idna", "base64_codec"])
def test_all_response_consumers_share_the_decoding_policy(http_lab, charset):
    encoding = charset if charset in {"iso-8859-1", "windows-1252"} else "utf-8"
    body = '<a href="/child"><input name="café"></a>'.encode(encoding)
    site = http_lab.start(lambda _: http_lab.reply(body=body, headers={"Content-Type": "text/html; charset=" + charset}))
    inventory = discover(site.url, max_depth=0, interval=0)
    assert inventory.errors == []
    assert any(endpoint.endpoint.endswith("/child") for endpoint in inventory.endpoints)

    text = evidence("café".encode(encoding), "text/plain; charset=" + charset)
    normal = replace(text, body="café".encode(), content_type="text/plain; charset=utf-8")
    assert extract_features(text).fingerprint == extract_features(normal).fingerprint

    html = evidence('<p>MARK café</p>'.encode(encoding), "text/html; charset=" + charset)
    probe = XssProbeEvidence(1, "marker_1", "q", "MARK", "MARK")
    assert inspect_response(probe, html, "callback").reflections == [{"context": "html_text"}]

    config = evidence("DB_HOST=café\nDB_PASSWORD=fictitious\n".encode(encoding), "text/plain; charset=" + charset)
    expected = replace(config, body="DB_HOST=café\nDB_PASSWORD=fictitious\n".encode(), content_type="text/plain; charset=utf-8")
    assert observe_exposure(config, "reference_1").features == observe_exposure(expected, "reference_1").features
