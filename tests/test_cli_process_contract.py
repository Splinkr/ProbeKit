"""CLI executada em subprocesso, como no terminal do Windows."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from experiments.sqlite_control import SAFE_PATH, VULNERABLE_PATH

PROJECT = Path(__file__).resolve().parents[1]


def invoke(*arguments, cwd):
    return subprocess.run(
        [sys.executable, str(PROJECT / "main.py"), *arguments], cwd=cwd,
        env={**os.environ, "PYTHONUTF8": "1"}, capture_output=True, text=True,
        encoding="utf-8", timeout=20,
    )


@pytest.mark.parametrize("option", ["--help", "--version"])
def test_informational_commands_run_without_a_target(tmp_path, option):
    process = invoke(option, cwd=tmp_path)
    assert process.returncode == 0 and process.stdout
    assert not list(tmp_path.rglob("*.json"))


def test_default_baseline_creates_a_report_in_the_callers_directory(http_lab, tmp_path):
    origin = http_lab.start(lambda _: http_lab.reply(body=b"terminal check"))
    process = invoke(origin.url, "--interval", "0", cwd=tmp_path)
    assert process.returncode == 0, process.stderr
    reports = list((tmp_path / "reports").glob("baseline-*.json"))
    assert len(reports) == 1
    report = json.loads(reports[0].read_text(encoding="utf-8"))
    assert report["summary"]["responses_received"] == len(origin.calls) == 2
    assert report["findings"] == []


@pytest.mark.parametrize("path,outcome,findings", [
    (VULNERABLE_PATH, "confirmed", 1), (SAFE_PATH, "not_detected", 0),
])
def test_sqli_terminal_output_agrees_with_saved_json(sqlite_app, tmp_path, path, outcome, findings):
    output = tmp_path / "cli-result.json"
    process = invoke(sqlite_app.url + path + "?q=apple", "--module", "sqli", "--interval", "0",
                     "--output", str(output), cwd=tmp_path)
    assert process.returncode == 0, process.stderr
    assert f"SQLi: {outcome}" in process.stdout
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["assessment"]["outcome"] == outcome
    assert len(report["findings"]) == findings


@pytest.mark.parametrize("arguments", [
    ["--samples", "0"], ["--timeout", "nan"], ["--timeout", "inf"],
    ["--interval", "-1"], ["--max-body-bytes", "0"], ["--module", "unsupported"],
    ["--samples", "3", "--max-requests", "2"],
    ["--module", "sqli", "--samples", "1"],
    ["--module", "sqli", "--max-requests", "9"],
])
def test_invalid_invocations_exit_two_without_contacting_target(http_lab, tmp_path, arguments):
    origin = http_lab.start(lambda _: http_lab.reply())
    process = invoke(origin.url + "/rest/products/search?q=apple", *arguments, cwd=tmp_path)
    assert process.returncode == 2
    assert origin.calls == []
    assert not list(tmp_path.rglob("*.json"))


def test_failed_collection_is_written_and_exits_one(http_lab, tmp_path):
    origin = http_lab.start(lambda _: http_lab.reply(body=b"too big"))
    output = tmp_path / "failure.json"
    process = invoke(origin.url, "--max-body-bytes", "1", "--output", str(output), cwd=tmp_path)
    assert process.returncode == 1
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["errors"][0]["kind"] == "response_too_large"
    assert report["summary"]["status"] == "incomplete"


def test_unwritable_destination_exits_one_with_a_clear_message(http_lab, tmp_path):
    origin = http_lab.start(lambda _: http_lab.reply())
    process = invoke(origin.url, "--samples", "1", "--output", str(tmp_path), cwd=tmp_path)
    assert process.returncode == 1
    assert "Erro ao gravar relatório" in process.stderr
