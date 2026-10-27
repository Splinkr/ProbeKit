import pytest

from scanner.targets import TargetError, validate_target


@pytest.mark.parametrize(("url", "expected"), [
    ("http://localhost:3000", "http://127.0.0.1:3000/"),
    ("https://LOCALHOST/a?q=x", "https://127.0.0.1/a?q=x"),
    ("http://127.0.0.2/", "http://127.0.0.2/"),
    ("http://[::1]:3000/a", "http://[::1]:3000/a"),
])
def test_normalize_loopback(url, expected):
    assert validate_target(url) == expected


@pytest.mark.parametrize("url", [
    "http://example.com", "http://192.168.1.1", "http://0.0.0.0",
    "http://[::]", "http://169.254.169.254", "http://127.0.0.1.example.com",
    "http://localhost.example.com", "http://localhost@8.8.8.8",
    "http://user:password@127.0.0.1", "http://2130706433", "http://127.1",
    "http://0x7f000001", "file:///etc/passwd", "localhost:3000",
    "http://127.0.0.1:65536", "http://127.0.0.1:0", "http://[::1",
    "http://[::1%25eth0]", "http://localhost/#route", "http://localhost/\n",
    "http://localhost\\@8.8.8.8/", "http://%6cocalhost/",
])
def test_reject_unsafe_or_ambiguous_targets(url):
    with pytest.raises(TargetError):
        validate_target(url)
