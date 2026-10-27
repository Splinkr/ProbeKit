import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

import pytest

from main import main
from scanner.targets import TargetError
from scanner.discovery import discover

ROOT = Path(__file__).resolve().parents[1]


def invoke(*args, cwd):
    return subprocess.run([sys.executable, str(ROOT / "main.py"), "discover", *args], cwd=cwd,
                          env={**os.environ, "PYTHONUTF8": "1"}, capture_output=True, text=True,
                          encoding="utf-8", timeout=20)


def test_discover_command_exports_inventory_with_automatic_and_manual_sources(http_lab, tmp_path):
    site = http_lab.start(lambda request: http_lab.reply(
        body=b'<a href="/items?category=demo">go</a><form action="/search"><input name="q"></form>' if request.path == "/" else b"done",
        headers={"Content-Type": "text/html"},
    ))
    output = tmp_path / "inventory.json"
    process = invoke(site.url, "--interval", "0", "--output", str(output), cwd=tmp_path)
    assert process.returncode == 0, process.stderr
    assert "Inventário JSON" in process.stdout
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["mode"] == "discover" and data["summary"]["endpoints"] == 3
    assert data["endpoints"][0]["provided_manually"]
    assert all(item["discovered_automatically"] for item in data["endpoints"][1:])
    assert {call.path for call in site.calls} == {"/", "/items"}


def test_discover_default_output_and_help(http_lab, tmp_path):
    site = http_lab.start(lambda _: http_lab.reply(body=b"<html>done</html>", headers={"Content-Type": "text/html"}))
    assert invoke("--help", cwd=tmp_path).returncode == 0
    process = invoke(site.url, cwd=tmp_path)
    assert process.returncode == 0, process.stderr
    assert len(list((tmp_path / "reports").glob("discover-*.json"))) == 1


@pytest.mark.parametrize("arguments", [
    ["--max-depth", "-1"], ["--max-pages", "0"], ["--max-requests", "0"],
    ["--timeout", "nan"], ["--interval", "-1"], ["--max-body-bytes", "0"],
])
def test_invalid_discovery_limits_exit_before_network(http_lab, tmp_path, arguments):
    site = http_lab.start(lambda _: http_lab.reply())
    assert invoke(site.url, *arguments, cwd=tmp_path).returncode == 2
    assert site.calls == []


@pytest.mark.parametrize("url", ["http://example.invalid", "http://192.168.0.1", "http://localhost/\n"])
def test_unsafe_seeds_are_blocked_before_transport(url, monkeypatch):
    send = Mock()
    monkeypatch.setattr("requests.Session.get", send)
    with pytest.raises(TargetError):
        discover(url)
    with pytest.raises(SystemExit) as failure:
        main(["discover", url])
    assert failure.value.code == 2
    send.assert_not_called()


def test_discovery_failure_keeps_json_and_exits_one(http_lab, tmp_path):
    site = http_lab.start(lambda _: http_lab.reply(body=b"long body"))
    output = tmp_path / "failed.json"
    process = invoke(site.url, "--max-body-bytes", "1", "--output", str(output), cwd=tmp_path)
    assert process.returncode == 1
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["summary"]["status"] == "incomplete"
    assert data["errors"][0]["kind"] == "response_too_large"
    assert data["endpoints"][0]["provided_manually"]


def test_discovery_write_failure_is_reported(http_lab, tmp_path):
    site = http_lab.start(lambda _: http_lab.reply())
    process = invoke(site.url, "--output", str(tmp_path), cwd=tmp_path)
    assert process.returncode == 1
    assert "Erro ao gravar inventário" in process.stderr
