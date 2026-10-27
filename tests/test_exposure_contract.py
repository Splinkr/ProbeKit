"""Artefatos reais fictícios, controles negativos, privacidade e orçamento dos três módulos."""

from dataclasses import asdict
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from unittest.mock import Mock
from urllib.parse import urlsplit

import pytest
import requests

from experiments import exposure_lab
from main import main
from scanner.exposure_profiles import FileSpec, build_plan, file_url, select_profiles
from scanner.modules.exposure import run_exposure
from scanner.pipeline import run_scan
from scanner.reporter import write_json_atomic
from scanner.xss_browser import browser_path

ROOT = Path(__file__).resolve().parents[1]


def text(lab, content, status=200, **headers):
    return lab.reply(body=content.encode(), status=status, headers={"Content-Type": "text/plain", **headers})


def assert_private(report):
    serialized = json.dumps(report.to_dict())
    for value in (*exposure_lab.SENTINELS, "DB_PASSWORD", "fictional_records", "fictitious-demo"):
        assert value not in serialized
    return serialized


def test_real_config_backup_block_and_public_document(sqlite_app):
    before = sqlite_app.server.database.manifest()
    report = run_exposure(sqlite_app.url + "/", profiles=("config", "backup"), max_requests=16, interval=0)
    assert [result.assessment.outcome for result in report.exposure_results] == ["confirmed", "not_detected", "confirmed", "not_detected"]
    assert len(report.responses) == 16 and len(report.findings) == 2
    assert all(finding.category == "exposure" for finding in report.findings)
    assert before == sqlite_app.server.database.manifest()
    assert_private(report)
    for response in report.responses:
        assert not hasattr(response, "body")
        assert "security_headers" not in asdict(response)
    assert all(value not in repr(report) for value in exposure_lab.SENTINELS)


def test_default_is_small_config_profile_and_controls_have_distinct_names(sqlite_app):
    report = run_exposure(sqlite_app.url + "/", interval=0)
    assert len(report.responses) == 8
    controls = [item.url for item in report.responses if item.role.startswith("control_")]
    assert len(controls) == len(set(controls)) == 4
    assert all("backup.sql" not in item.url and ".git/HEAD" not in item.url for item in report.responses)


def test_all_profiles_are_bounded_and_recognize_all_supported_formats(sqlite_app):
    report = run_exposure(sqlite_app.url + "/exposure-lab/exposed/", profiles=("config", "backup", "repository", "config"),
                          max_requests=20, interval=0)
    assert len(select_profiles(("config", "backup", "repository"))) == 5
    assert len(report.exposure_results) == 5 and len(report.responses) == 20
    assert all(result.assessment.outcome == "confirmed" for result in report.exposure_results)
    assert_private(report)


@pytest.mark.parametrize("branch", ["fallback", "error", "blocked"])
def test_generic_html_custom_errors_and_denials_do_not_confirm(sqlite_app, branch):
    report = run_exposure(sqlite_app.url + f"/exposure-lab/{branch}/", profiles=("config", "backup"), max_requests=16, interval=0)
    assert all(result.assessment.outcome == "not_detected" for result in report.exposure_results)
    assert report.findings == [] and len(report.responses) == 16
    if branch == "fallback":
        assert all(not result.assessment.checks["different_from_missing_paths"] for result in report.exposure_results)
    if branch == "error":
        assert all(item.features.error_like for item in report.responses)


def test_sensitive_structure_returned_for_every_path_is_not_specific_file_proof(http_lab):
    site = http_lab.start(lambda _: text(http_lab, exposure_lab.CONFIG_TEXT))
    report = run_exposure(site.url + "/", interval=0)
    assert report.exposure_results[0].assessment.outcome == "inconclusive"
    assert report.findings == []
    assert not report.exposure_results[0].assessment.checks["different_from_missing_paths"]
    assert_private(report)


def test_path_name_and_http_200_cannot_override_public_document_content(http_lab):
    site = http_lab.start(lambda _: text(http_lab, exposure_lab.PUBLIC_TEXT))
    report = run_exposure(site.url + "/", profiles=("config", "backup"), max_requests=16, interval=0)
    assert all(result.assessment.outcome == "not_detected" for result in report.exposure_results)
    assert not report.findings


def test_swapping_content_changes_outcome_without_renaming_path(sqlite_app, monkeypatch):
    monkeypatch.setattr(exposure_lab, "CONFIG_TEXT", exposure_lab.PUBLIC_TEXT)
    report = run_exposure(sqlite_app.url + "/", interval=0)
    assert report.exposure_results[0].url.endswith("/.env")
    assert report.exposure_results[0].assessment.outcome == "not_detected"


@pytest.mark.parametrize("content,mime,expected", [
    ("<html><title>Generic</title><p>password secret backup</p></html>", "application/octet-stream", "not_detected"),
    ("password secret token backup config", "text/plain", "not_detected"),
    ("<pre>\n" + exposure_lab.CONFIG_TEXT + "</pre>", "text/html", "suspected"),
    ("# README\n" + exposure_lab.BACKUP_TEXT, "text/plain", "not_detected"),
])
def test_content_structure_html_sniff_and_public_context(http_lab, content, mime, expected):
    site = http_lab.start(lambda request: text(http_lab, content, **{"Content-Type": mime})
                          if request.path in {"/.env", "/backup.sql"} else text(http_lab, "Not found: " + request.path, 404))
    report = run_exposure(site.url + "/", profiles=("config", "backup"), max_requests=16, interval=0)
    selected = report.exposure_results[2] if content.startswith("# README") else report.exposure_results[0]
    assert selected.assessment.outcome == expected
    assert all(finding.status != "confirmed" for finding in report.findings)


@pytest.mark.parametrize("unstable", ["references", "controls"])
def test_instability_retains_only_suspicion(http_lab, unstable):
    def respond(request):
        if request.path == "/.env":
            suffix = f"# varying {request.number}" if unstable == "references" else ""
            return text(http_lab, exposure_lab.CONFIG_TEXT + suffix)
        suffix = str(request.number) if unstable == "controls" else ""
        return text(http_lab, "Not found " + request.path + suffix, 404)
    site = http_lab.start(respond)
    report = run_exposure(site.url + "/", interval=0)
    assert report.exposure_results[0].assessment.outcome == "suspected"
    assert all(finding.status != "confirmed" for finding in report.findings)
    assert_private(report)


def test_secret_values_keys_and_arbitrary_headers_never_enter_report(http_lab):
    private_header = "EXPOSURE_FAKE_HEADER_1742"
    def respond(request):
        if request.path == "/.env":
            return text(http_lab, exposure_lab.CONFIG_TEXT, **{
                "Content-Type": "text/plain; note=" + private_header,
                "Content-Security-Policy": "script-src 'nonce-" + private_header + "'",
                "Content-Disposition": 'attachment; filename="' + private_header + '"',
            })
        return text(http_lab, "Not found: " + request.path, 404)
    site = http_lab.start(respond)
    report = run_exposure(site.url + "/", interval=0)
    assert report.exposure_results[0].assessment.outcome == "confirmed"
    assert private_header not in assert_private(report)
    assert all(item.content_type == "text/plain" for item in report.responses)


@pytest.mark.parametrize("status", [401, 403, 404, 410])
def test_blocked_and_missing_files_are_negative(http_lab, status):
    site = http_lab.start(lambda _: text(http_lab, "Unavailable", status))
    report = run_exposure(site.url + "/", interval=0)
    assert all(result.assessment.outcome == "not_detected" for result in report.exposure_results)
    assert not report.findings


@pytest.mark.parametrize("status", [302, 429, 500])
def test_unsupported_http_statuses_are_inconclusive(http_lab, status):
    sink = http_lab.start(lambda _: text(http_lab, "Should not receive traffic"))
    site = http_lab.start(lambda _: text(http_lab, "Unavailable", status, Location=sink.url))
    report = run_exposure(site.url + "/", interval=0)
    assert all(result.assessment.outcome == "inconclusive" for result in report.exposure_results)
    assert sink.calls == [] and not report.findings


@pytest.mark.parametrize("url,options", [
    ("http://example.invalid/", {}), ("http://192.168.1.2/", {}),
    ("http://localhost/?token=value", {}), ("http://localhost/path", {}),
    ("http://localhost/../", {}), ("http://localhost/%2e%2e/", {}),
    ("http://localhost/", {"profiles": ("unknown",)}), ("http://localhost/", {"profiles": ()}),
    ("http://localhost/", {"samples": 1}), ("http://localhost/", {"max_requests": 7}),
])
def test_invalid_scope_profiles_or_budget_fail_before_network(monkeypatch, url, options):
    send = Mock()
    monkeypatch.setattr(requests.Session, "get", send)
    with pytest.raises(ValueError):
        run_exposure(url, **options)
    send.assert_not_called()


def test_unknown_files_cannot_be_added_via_the_profile_api():
    with pytest.raises(ValueError):
        file_url("http://localhost/", FileSpec("README.txt", "config", "dotenv"))
    plan = build_plan("http://localhost/app/", select_profiles()[0])
    assert all(url.startswith("http://127.0.0.1/app/") for _, url in plan)


def test_exposure_honors_three_reference_samples(sqlite_app):
    report = run_exposure(sqlite_app.url + "/", samples=3, max_requests=10, interval=0)
    assert len(report.responses) == 10
    assert report.exposure_results[0].assessment.outcome == "confirmed"


@pytest.mark.parametrize("budget", [1, 6, 9, 10, 13, 14, 17, 18, 21, 22])
def test_exposure_shares_discovery_budget_and_never_starts_incomplete_plan(sqlite_app, budget):
    report = run_scan(sqlite_app.url + "/probekit-lab", modules=("exposure",),
                      exposure_profiles=("config", "backup", "config"), max_requests=budget, interval=0)
    discovery = min(6, budget)
    files = min(4, (budget - discovery) // 4)
    assert len(report.requests) == discovery + files * 4 <= budget
    assert report.to_dict()["summary"]["files_analyzed"] == files
    assert report.to_dict()["summary"]["parameters_analyzed"] == 0
    assert len(report.targets) == 4
    assert [item["request_id"] for item in report.requests] == list(range(1, len(report.requests) + 1))
    assert all(target["url"].rsplit("/", 1)[-1] != "README.txt" for target in report.targets)
    assert_private(report)


def test_three_modules_have_independent_results_and_one_budget(sqlite_app):
    report = run_scan(sqlite_app.url + "/probekit-lab", modules=("sqli", "xss", "exposure"),
                      exposure_profiles=("config", "backup"), interval=0)
    data = report.to_dict()
    assert report.status == "completed"
    assert data["summary"]["requests_used"] == 92
    assert data["summary"]["discovery_requests"] == 6
    assert data["summary"]["parameters_analyzed"] == 8
    assert data["summary"]["files_analyzed"] == 4
    assert {analysis.mode for analysis in report.analyses} == {"sqli", "xss", "exposure"}
    assert len(data["exposure_results"]) == 4
    assert_private(report)


@pytest.mark.skipif(not browser_path() or not shutil.which("node"), reason="Confirmação opcional requer navegador e Node locais.")
def test_three_modules_with_real_browser_and_no_file_content_leak(sqlite_app):
    report = run_scan(sqlite_app.url + "/probekit-lab", modules=("sqli", "xss", "exposure"),
                      exposure_profiles=("config", "backup"), interval=0, xss_browser=True)
    assert report.status == "completed" and len(report.requests) == 92
    assert sum(finding.status == "confirmed" for analysis in report.analyses for finding in analysis.findings) == 4
    assert_private(report)


def test_explicit_subdirectory_is_used_once_for_profile_targets(sqlite_app):
    report = run_scan(sqlite_app.url + "/probekit-lab", modules=("exposure",), interval=0,
                      exposure_profiles=("config", "backup"), exposure_base_path="/exposure-lab/exposed/")
    assert report.to_dict()["summary"]["files_analyzed"] == 4
    assert all(item["url"].startswith(sqlite_app.url + "/exposure-lab/exposed/") for item in report.requests if item["phase"] == "analysis")
    assert all(analysis.assessment.outcome == "confirmed" for analysis in report.analyses)


def test_size_limit_discards_content_and_preserves_partial_evidence(http_lab):
    site = http_lab.start(lambda request: text(http_lab, exposure_lab.CONFIG_TEXT * 100)
                          if request.path == "/.env" else text(http_lab, "Not found", 404))
    report = run_exposure(site.url + "/", max_body_bytes=256, interval=0)
    assert report.errors[0].kind == "response_too_large"
    assert report.exposure_results[0].assessment.outcome == "inconclusive"
    assert len(report.responses) + len(report.errors) == 6
    assert_private(report)


def test_interrupt_keeps_only_safe_partial_evidence(sqlite_app, monkeypatch, tmp_path):
    original, calls = requests.Session.get, 0
    def interrupt(session, *args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 9:
            raise KeyboardInterrupt
        return original(session, *args, **kwargs)
    monkeypatch.setattr(requests.Session, "get", interrupt)
    output = tmp_path / "partial.json"
    report = run_scan(sqlite_app.url + "/probekit-lab", modules=("exposure",), interval=0,
                      checkpoint=lambda current: write_json_atomic(current, output))
    assert report.status == "interrupted" and len(report.requests) == 9
    assert report.analyses[0].assessment.outcome == "inconclusive"
    serialized = assert_private(report)
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["status"] == "interrupted"
    assert all(value not in serialized for value in exposure_lab.SENTINELS)


def test_cli_direct_and_three_modules_preserve_safe_json_and_stdout(sqlite_app, tmp_path):
    def invoke(*args):
        return subprocess.run([sys.executable, str(ROOT / "main.py"), *args], cwd=tmp_path,
            env={**os.environ, "PYTHONUTF8": "1"}, capture_output=True, text=True, encoding="utf-8", timeout=30)
    direct = tmp_path / "exposure.json"
    result = invoke(sqlite_app.url + "/", "--module", "exposure", "--exposure-profiles", "config", "backup", "--max-requests", "16",
                    "--interval", "0", "--output", str(direct))
    assert result.returncode == 0, result.stderr
    assert "Exposure: confirmed" in result.stdout
    assert json.loads(direct.read_text(encoding="utf-8"))["summary"]["files_analyzed"] == 4
    assert all(value not in result.stdout + result.stderr + direct.read_text(encoding="utf-8") for value in exposure_lab.SENTINELS)
    combined = tmp_path / "combined.json"
    result = invoke("scan", sqlite_app.url + "/probekit-lab", "--modules", "sqli", "xss", "exposure", "--exposure-profiles", "config", "backup",
                    "--interval", "0", "--output", str(combined))
    assert result.returncode == 0, result.stderr
    data = json.loads(combined.read_text(encoding="utf-8"))
    assert data["summary"]["requests_used"] == 92 and len(data["exposure_results"]) == 4


@pytest.mark.parametrize("arguments", [
    ["--modules", "exposure", "--exposure-base-path", "//example.invalid/"],
    ["--modules", "sqli", "--exposure-profiles", "config"],
    ["--modules", "exposure", "--exposure-profiles", "unknown"],
])
def test_invalid_scan_profile_or_origin_is_rejected_before_network(monkeypatch, arguments):
    send = Mock()
    monkeypatch.setattr(requests.Session, "get", send)
    with pytest.raises(SystemExit) as failure:
        main(["scan", "http://localhost/", *arguments])
    assert failure.value.code == 2
    send.assert_not_called()
