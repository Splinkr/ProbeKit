"""Falhas reais possíveis no filesystem Windows, sem repetir requisições HTTP."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from scanner.pipeline import run_scan
from scanner.reporter import write_json_atomic


def windows_lock():
    error = PermissionError("Checkpoint temporariamente bloqueado")
    error.winerror = 5
    return error


def test_transient_windows_lock_retries_replace_without_losing_valid_json(tmp_path, monkeypatch):
    output = tmp_path / "scan.json"
    output.write_text('{"previous":true}', encoding="utf-8")
    report = Mock()
    report.to_dict.return_value = {"current": True}
    original, attempts = Path.replace, []

    def replace(source, target):
        attempts.append(source)
        if len(attempts) < 3:
            assert json.loads(output.read_text(encoding="utf-8")) == {"previous": True}
            raise windows_lock()
        return original(source, target)

    sleep = Mock()
    monkeypatch.setattr(Path, "replace", replace)
    monkeypatch.setattr("scanner.reporter.time.sleep", sleep)
    write_json_atomic(report, output)
    assert len(attempts) == 3 and len(set(attempts)) == 1
    assert sleep.call_count == 2
    assert json.loads(output.read_text(encoding="utf-8")) == {"current": True}
    assert not list(tmp_path.glob(".scan-*.tmp"))


@pytest.mark.parametrize("windows", [True, False])
def test_permanent_denial_keeps_previous_report_and_cleans_temporary(tmp_path, monkeypatch, windows):
    output = tmp_path / "scan.json"
    output.write_text('{"previous":true}', encoding="utf-8")
    report = Mock()
    report.to_dict.return_value = {"current": True}
    replace = Mock(side_effect=windows_lock() if windows else PermissionError("Denied"))
    monkeypatch.setattr(Path, "replace", replace)
    monkeypatch.setattr("scanner.reporter.time.sleep", Mock())
    with pytest.raises(PermissionError):
        write_json_atomic(report, output)
    assert replace.call_count == (4 if windows else 1)
    assert json.loads(output.read_text(encoding="utf-8")) == {"previous": True}
    assert not list(tmp_path.glob(".scan-*.tmp"))


def test_failed_checkpoint_cannot_mark_unfinished_scan_as_completed(sqlite_app, tmp_path):
    output = tmp_path / "scan.json"
    attempts = 0

    def checkpoint(report):
        nonlocal attempts
        attempts += 1
        if attempts == 3:
            raise OSError("Simulated output failure")
        write_json_atomic(report, output)

    with pytest.raises(OSError):
        run_scan(sqlite_app.url + "/probekit-lab", modules=("exposure",), interval=0, checkpoint=checkpoint)
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["summary"]["status"] == "incomplete"
    assert "checkpoint_error" in data["stop_reasons"]
    assert data["summary"]["files_analyzed"] == 1
    assert data["summary"]["requests_used"] == 10
