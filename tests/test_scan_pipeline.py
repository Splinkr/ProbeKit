"""Fluxo integrado real, orçamento único e interrupções controladas no loopback."""

import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from main import main
from scanner.pipeline import ScopedHttpClient, run_scan
from scanner.reporter import write_json_atomic
from scanner.targets import TargetError

ROOT = Path(__file__).resolve().parents[1]


def html(lab, body, **options):
    return lab.reply(body=body.encode(), headers={"Content-Type": "text/html"}, **options)


def invoke(*arguments, cwd):
    return subprocess.run([sys.executable, str(ROOT / "main.py"), *arguments], cwd=cwd,
                          env={**os.environ, "PYTHONUTF8": "1"}, capture_output=True,
                          text=True, encoding="utf-8", timeout=30)


def test_html_to_sqlite_end_to_end_without_route_or_classification_shortcuts(sqlite_app):
    before = sqlite_app.server.database.manifest()
    report = run_scan(sqlite_app.url + "/scan-lab", interval=0)
    data = report.to_dict()
    assert report.status == "completed"
    assert data["summary"]["requests_used"] == 85
    assert data["summary"]["discovery_requests"] == 5
    assert data["summary"]["analysis_requests"] == 80
    assert data["summary"]["parameters_analyzed"] == 8
    assert data["summary"]["findings"] == 2
    outcomes = {(urlsplit(result["url"]).path, result["parameter"]): result["assessment"]["outcome"]
                for result in data["parameter_results"]}
    for kind, parameter in (("json", "term"), ("html", "search")):
        assert outcomes[(f"/general/{kind}/vulnerable", parameter)] == "confirmed"
        assert outcomes[(f"/general/{kind}/safe", parameter)] == "not_detected"
        for route in ("vulnerable", "safe"):
            assert outcomes[(f"/general/{kind}/{route}", "lang")] == "not_detected"
    assert [entry["request_id"] for entry in report.requests] == list(range(1, 86))
    assert all(origin["url"].startswith(sqlite_app.url + "/") for origin in report.requests)
    assert before == sqlite_app.server.database.manifest()
    assert all(analysis["target_source"] == "automatic" for analysis in data["analyses"])
    assert any(item["reason"] == "duplicate_target" for item in report.ignored_targets)
    assert any(item["reason"] == "form_reference_values_unavailable" for item in report.ignored_targets)
    assert any(item["reason"] == "invalid_or_non_loopback_url" for item in report.ignored_targets)
    assert all("/general/text/" not in endpoint.endpoint for endpoint in report.discovery.endpoints)
    assert all("body" not in response for analysis in data["analyses"] for response in analysis["responses"])


@pytest.mark.parametrize("budget", [1, 4, 5, 14, 15, 24, 25, 84, 85, 100])
def test_discovery_and_analysis_share_one_hard_budget(sqlite_app, budget):
    report = run_scan(sqlite_app.url + "/scan-lab", max_requests=budget, interval=0)
    discovery_count = min(budget, 5)
    plans = min(8, (budget - discovery_count) // 10)
    expected = discovery_count + plans * 10
    summary = report.to_dict()["summary"]
    assert summary["requests_used"] == expected <= budget
    assert summary["discovery_requests"] == discovery_count
    assert summary["analysis_requests"] == plans * 10
    assert len(report.analyses) == plans
    assert [item["request_id"] for item in report.requests] == list(range(1, expected + 1))
    skipped = [item for item in report.ignored_targets if item["reason"] == "insufficient_global_budget"]
    assert len(skipped) == 8 - plans
    assert all(item["remaining_requests"] < item["required_requests"] for item in skipped)
    assert report.status == ("limited" if plans < 8 else "completed")


def test_depth_zero_does_not_attack_links_beyond_the_configured_depth(sqlite_app):
    report = run_scan(sqlite_app.url + "/scan-lab", max_depth=0, interval=0)
    assert len(report.requests) == 1
    assert report.analyses == []
    assert "max_depth" in report.stop_reasons
    assert any(item["reason"] == "max_depth" for item in report.ignored_targets)


def test_page_limit_only_bounds_discovery_and_remaining_budget_can_test_links(sqlite_app):
    report = run_scan(sqlite_app.url + "/scan-lab", max_pages=1, max_requests=81, interval=0)
    assert report.discovery.requests_attempted == 1
    assert len(report.requests) == 81
    assert len(report.analyses) == 8
    assert report.status == "limited" and "max_pages" in report.stop_reasons


def test_canonical_duplicates_collapse_but_distinct_reference_values_survive(sqlite_app, monkeypatch):
    monkeypatch.setattr("experiments.sqlite_control.SCAN_LAB_HTML", '''
        <a href="/control/vulnerable/search?q=apple">first</a>
        <a href="/control/./vulnerable/search?q=%61pple#top">duplicate</a>
        <a href="/control/vulnerable/search?q=orange">different value</a>''')
    report = run_scan(sqlite_app.url + "/scan-lab", interval=0)
    assert len(report.targets) == len(report.analyses) == 2
    assert len(report.requests) == 23
    assert all(analysis.assessment.outcome == "confirmed" for analysis in report.analyses)
    assert len([item for item in report.ignored_targets if item["reason"] == "duplicate_target"]) == 1


def test_repeated_and_empty_unselected_fields_are_preserved_without_inventing_values(http_lab):
    def respond(request):
        if request.path == "/":
            return html(http_lab, '<a href="/search?q=apple&amp;tag=a&amp;tag=b&amp;empty=">go</a>')
        return http_lab.reply(body=b'{"items":[{"id":1}]}', headers={"Content-Type": "application/json"})

    site = http_lab.start(respond)
    report = run_scan(site.url, interval=0)
    assert len(report.analyses) == 1 and report.analyses[0].assessment.parameter == "q"
    assert report.analyses[0].assessment.outcome == "not_detected"
    assert all(call.query["tag"] == ["a", "b"] and call.query["empty"] == [""] for call in site.calls[1:])
    assert {item["parameter"] for item in report.ignored_targets if item["reason"] == "unsupported_parameter_reference"} == {"tag", "empty"}


@pytest.mark.parametrize("external", [True, False])
def test_external_and_other_port_references_and_redirects_never_receive_traffic(http_lab, external):
    sink = http_lab.start(lambda _: http_lab.reply())
    location = "http://example.invalid/no-traffic" if external else sink.url + "/no-traffic"

    def respond(request):
        if request.path == "/":
            return html(http_lab, f'<a href="/bounce?q=apple">redirect</a><a href="{location}?q=apple">blocked</a>')
        return http_lab.reply(status=302, headers={"Location": location})

    site = http_lab.start(respond)
    report = run_scan(site.url, interval=0)
    assert len(site.calls) == len(report.requests) == 2 and sink.calls == []
    assert report.analyses == []
    assert any(item["reason"] == "redirect_not_followed" for item in report.ignored_targets)
    assert any(item["reason"] in {"different_origin", "invalid_or_non_loopback_url"} for item in report.ignored_targets)


def test_redirects_during_sql_probes_remain_evidence_without_following_them(http_lab):
    sink = http_lab.start(lambda _: http_lab.reply())

    def respond(request):
        if request.path == "/":
            return html(http_lab, '<a href="/search?q=apple">go</a>')
        if request.query["q"] != ["apple"]:
            return http_lab.reply(status=302, headers={"Location": sink.url})
        return http_lab.reply(body=b'{"items":[{"id":1}]}', headers={"Content-Type": "application/json"})

    site = http_lab.start(respond)
    report = run_scan(site.url, interval=0)
    assert sink.calls == [] and len(report.requests) == 12
    assert report.analyses[0].assessment.outcome == "inconclusive"
    assert report.analyses[0].findings == [] and report.status == "incomplete"


@pytest.mark.parametrize("status", [404, 500])
def test_http_error_pages_are_recorded_and_not_sent_to_sqli(http_lab, status):
    site = http_lab.start(lambda request: html(http_lab, '<a href="/error?q=apple">go</a>')
                          if request.path == "/" else http_lab.reply(status=status))
    report = run_scan(site.url, interval=0)
    assert len(report.requests) == 2 and report.analyses == []
    assert any(item["reason"] == "discovery_http_error" for item in report.ignored_targets)
    assert report.discovery.pages[-1]["status_code"] == status


def test_discovery_transport_failures_consume_budget_and_keep_the_inventory(http_lab):
    site = http_lab.start(lambda request: html(http_lab, '<a href="/large?q=apple">go</a>')
                          if request.path == "/" else http_lab.reply(body=b"x" * 1024))
    report = run_scan(site.url, interval=0, max_body_bytes=256)
    assert len(report.requests) == 2 and report.status == "incomplete"
    assert report.requests[-1]["error"] == "response_too_large"
    assert any(item["reason"] == "discovery_transport_failure" for item in report.ignored_targets)


def test_analysis_timeout_preserves_partial_result_and_continues_next_target(http_lab):
    counts = {}

    def respond(request):
        if request.path == "/":
            return html(http_lab, '<a href="/slow?q=apple">slow</a><a href="/good?q=apple">good</a>')
        counts[request.path] = counts.get(request.path, 0) + 1
        return http_lab.reply(body=b'{"items":[{"id":1}]}', headers={"Content-Type": "application/json"},
                              wait_headers=0.15 if request.path == "/slow" and counts[request.path] > 1 else 0)

    site = http_lab.start(respond)
    report = run_scan(site.url, interval=0, timeout=0.05)
    assert len(report.requests) == 14
    assert [analysis.assessment.outcome for analysis in report.analyses] == ["inconclusive", "not_detected"]
    assert report.analyses[0].errors[0].kind == "timeout"
    assert report.status == "incomplete"


@pytest.mark.parametrize("interrupt_at", [1, 2, 8, 16])
def test_interruptions_preserve_discovery_completed_and_partial_analyses(sqlite_app, monkeypatch, tmp_path, interrupt_at):
    original = requests.Session.get
    attempts = 0

    def interrupt(session, *args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == interrupt_at:
            raise KeyboardInterrupt
        return original(session, *args, **kwargs)

    monkeypatch.setattr(requests.Session, "get", interrupt)
    path = tmp_path / "partial.json"
    report = run_scan(sqlite_app.url + "/scan-lab", interval=0,
                      checkpoint=lambda current: write_json_atomic(current, path))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert report.status == data["summary"]["status"] == "interrupted"
    assert len(report.requests) == data["summary"]["requests_used"] == interrupt_at
    assert report.requests[-1]["status"] == "interrupted"
    failures = [error for analysis in report.analyses for error in analysis.errors]
    if failures:
        assert failures[-1].url == report.requests[-1]["url"]
    assert "user_interrupt" in report.stop_reasons
    assert data["discovery"]["endpoints"]
    if interrupt_at == 16:
        assert len(data["analyses"]) == 2
        assert data["analyses"][0]["assessment"]["outcome"] == "not_detected"
        assert data["analyses"][1]["assessment"]["outcome"] == "inconclusive"
    assert not list(tmp_path.glob(".scan-*.tmp"))


def test_atomic_checkpoint_does_not_replace_a_valid_report_on_serialization_failure(tmp_path):
    output = tmp_path / "scan.json"
    output.write_text('{"previous":"valid"}', encoding="utf-8")
    bad_report = Mock()
    bad_report.to_dict.return_value = {"invalid": object()}
    with pytest.raises(TypeError):
        write_json_atomic(bad_report, output)
    assert json.loads(output.read_text(encoding="utf-8")) == {"previous": "valid"}
    assert not list(tmp_path.glob(".scan-*.tmp"))


def test_scan_cli_exports_the_real_pipeline_and_legacy_commands_still_work(sqlite_app, tmp_path):
    output = tmp_path / "scan.json"
    result = invoke("scan", sqlite_app.url + "/scan-lab", "--interval", "0", "--output", str(output), cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "Requisições: 85/100" in result.stdout
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["mode"] == "scan" and data["summary"]["findings"] == 2
    for command in ([], ["discover"]):
        legacy = invoke(*command, sqlite_app.url + "/scan-lab", "--interval", "0",
                        "--output", str(tmp_path / f"legacy-{len(command)}.json"), cwd=tmp_path)
        assert legacy.returncode == 0, legacy.stderr
    assert invoke("scan", "--help", cwd=tmp_path).returncode == 0


def test_cli_interruption_returns_130_and_keeps_json(http_lab, monkeypatch, tmp_path):
    site = http_lab.start(lambda _: http_lab.reply())
    monkeypatch.setattr(requests.Session, "get", Mock(side_effect=KeyboardInterrupt))
    output = tmp_path / "interrupted.json"
    assert main(["scan", site.url, "--output", str(output)]) == 130
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["status"] == "interrupted"


def test_invalid_output_stops_before_any_request(http_lab, tmp_path):
    site = http_lab.start(lambda _: http_lab.reply())
    assert main(["scan", site.url, "--output", str(tmp_path)]) == 1
    assert site.calls == []


@pytest.mark.parametrize("options", [
    ["--samples", "1"], ["--max-depth", "-1"], ["--max-pages", "0"],
    ["--max-requests", "0"], ["--timeout", "nan"], ["--interval", "-1"],
    ["--max-body-bytes", "0"], ["--sqli-context", "unknown"],
])
def test_invalid_scan_options_fail_before_network(http_lab, options):
    site = http_lab.start(lambda _: http_lab.reply())
    with pytest.raises(SystemExit) as failure:
        main(["scan", site.url, *options])
    assert failure.value.code == 2 and site.calls == []


@pytest.mark.parametrize("destination", ["http://example.invalid/", "http://127.0.0.2/", "http://127.0.0.1:9999/"])
def test_shared_transport_blocks_destinations_outside_authorized_origin_before_counting(monkeypatch, destination):
    send = Mock()
    monkeypatch.setattr(requests.Session, "get", send)
    ledger = []
    with ScopedHttpClient("http://127.0.0.1:8001/", ledger) as client:
        with pytest.raises(TargetError):
            client.get(destination)
        assert client.request_count == 0 and ledger == []
    send.assert_not_called()


def test_quoted_profile_can_be_selected_for_the_integrated_scan(sqlite_app, monkeypatch):
    monkeypatch.setattr("experiments.sqlite_control.SCAN_LAB_HTML", '''
        <a href="/general/quoted/vulnerable?item=Apple+Demo">positive</a>
        <a href="/general/quoted/safe?item=Apple+Demo">negative</a>''')
    report = run_scan(sqlite_app.url + "/scan-lab", context="quoted", interval=0)
    assert [analysis.assessment.outcome for analysis in report.analyses] == ["confirmed", "not_detected"]
    assert len(report.requests) == 23
