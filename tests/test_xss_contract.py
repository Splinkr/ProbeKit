"""Reflexão real, contextos, controles e navegador isolado no loopback."""

from html import escape
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from main import main
from scanner.modules.xss import build_plan, run_xss
from scanner.pipeline import run_scan
from scanner.reporter import write_json_atomic
from scanner.xss_analysis import ReflectionParser
from scanner.xss_browser import browser_path

ROOT = Path(__file__).resolve().parents[1]
HAS_BROWSER = bool(browser_path() and shutil.which("node"))


@pytest.mark.parametrize("path,outcome", [
    ("/xss/html/raw", "suspected"), ("/xss/html/escaped", "reflected_safe"),
    ("/xss/attribute/raw", "suspected"), ("/xss/attribute/escaped", "reflected_safe"),
    ("/xss/json", "reflected_safe"), ("/xss/script/raw", "suspected"),
    ("/xss/csp", "suspected"), ("/xss/text", "reflected_safe"),
])
def test_static_reflection_is_never_execution_proof(sqlite_app, path, outcome):
    report = run_xss(sqlite_app.url + path + "?q=demo", interval=0)
    assert report.assessment.outcome == outcome
    assert report.assessment.checks["two_marker_reflections"]
    assert not report.assessment.checks["browser_execution_observed"]
    assert len(report.responses) == 10 and not report.errors
    assert all(finding.status != "confirmed" for finding in report.findings)
    assert all("body" not in response for response in report.to_dict()["responses"])


@pytest.mark.skipif(not HAS_BROWSER, reason="Confirmação opcional requer navegador local e Node.")
@pytest.mark.parametrize("path,outcome", [
    ("/xss/html/raw", "confirmed"), ("/xss/attribute/raw", "confirmed"),
    ("/xss/script/raw", "confirmed"), ("/xss/csp", "suspected"),
    ("/xss/script/escaped", "suspected"),
])
def test_real_browser_callback_and_csp_control(sqlite_app, path, outcome):
    report = run_xss(sqlite_app.url + path + "?q=demo", interval=0, browser=True)
    assert report.assessment.outcome == outcome
    proof = report.assessment.browser_evidence
    assert proof["status"] == "completed"
    assert proof["target_network_requests"] == 0
    assert proof["cases"][0]["replayed"] and not proof["cases"][0]["executed"]
    assert all(case["csp_preserved"] for case in proof["cases"])
    assert proof["confirmed"] == (outcome == "confirmed")
    assert len(report.responses) == 10


@pytest.mark.parametrize("path", ["/xss/html/escaped", "/xss/attribute/escaped", "/xss/json", "/xss/text"])
def test_inert_and_escaped_reflections_do_not_invoke_browser(sqlite_app, monkeypatch, path):
    browser = Mock(side_effect=AssertionError("Reflexão inerte não deve ser confirmada artificialmente"))
    monkeypatch.setattr("scanner.xss_browser.confirm_responses", browser)
    report = run_xss(sqlite_app.url + path + "?q=demo", interval=0, browser=True)
    assert report.assessment.outcome == "reflected_safe" and not report.findings
    assert report.assessment.browser_evidence["status"] == "not_needed"
    browser.assert_not_called()


def test_markers_are_unique_across_parameters_and_runs():
    plans = [build_plan("http://localhost:8004/echo?q=demo", "q")[0] for _ in range(3)]
    markers = [probe.marker for plan in plans for probe in plan if probe.marker]
    assert len(markers) == len(set(markers)) == 21
    assert all(probe.marker is None for plan in plans for probe in plan if probe.role.startswith("baseline") or probe.role == "recovery")
    assert all("cookie" not in probe.input_value.lower() and "fetch(" not in probe.input_value for plan in plans for probe in plan)


def test_preexisting_marker_invalidates_confirmation(http_lab, monkeypatch):
    monkeypatch.setattr("scanner.modules.xss.secrets.token_hex", lambda _: "a" * 24)
    marker = "WVX" + "a" * 24 + "A"
    site = http_lab.start(lambda request: http_lab.reply(
        body=("<p>" + marker + request.query["q"][0] + "</p>").encode(), headers={"Content-Type": "text/html"}))
    report = run_xss(site.url + "?q=demo", interval=0, browser=True)
    assert report.assessment.outcome == "inconclusive"
    assert not report.assessment.checks["exclusive_markers_and_recovery"]
    assert not report.findings


def test_numeric_html_entities_are_recognized_as_escape(http_lab):
    def respond(request):
        value = ''.join(f"&#{ord(char)};" if char in '<>&"\'' else char for char in request.query["q"][0])
        return http_lab.reply(body=("<p>" + value + "</p>").encode(), headers={"Content-Type": "text/html"})
    site = http_lab.start(respond)
    report = run_xss(site.url + "?q=demo", interval=0)
    assert report.assessment.outcome == "reflected_safe"
    probe = next(probe for probe in report.probes if probe.role == "escape")
    assert set(probe.escaping.values()) == {"html_entity"}


@pytest.mark.parametrize("body,expected", [
    ("<p>MARK</p>", "html_text"), ('<input value="MARK">', "html_attribute"),
    ('<a href="MARK">link</a>', "url_attribute"), ('<div onclick="MARK">go</div>', "event_handler"),
    ("<script>const echo='MARK';</script>", "script"), ('<script type="application/json">"MARK"</script>', "script_data"),
    ("<textarea>MARK</textarea>", "html_rcdata"), ("<!--MARK-->", "html_comment"),
    ("<template><script>MARK</script></template>", "inert_template"),
])
def test_context_parser_records_location_without_claiming_execution(body, expected):
    parser = ReflectionParser("MARK", "callback")
    parser.feed(body)
    parser.close()
    assert any(item["context"] == expected for item in parser.reflections)
    assert not parser.active_script_marker


def test_multiple_parameters_preserve_others_and_early_negative_ids_stay_global(sqlite_app):
    report = run_xss(sqlite_app.url + "/xss/html/escaped?q=demo&lang=en", all_parameters=True, max_requests=20, interval=0)
    assert [result.assessment.outcome for result in report.parameter_results] == ["reflected_safe", "not_detected"]
    assert len(report.responses) == 15
    assert [response.request_id for response in report.responses] == list(range(1, 16))
    for probe, response in zip(report.probes, report.responses):
        query = parse_qs(urlsplit(response.url).query)
        assert query["lang"] == ["en"] if probe.parameter == "q" else query["q"] == ["demo"]


@pytest.mark.parametrize("budget,used,analyses", [(1, 1, 0), (10, 5, 0), (15, 15, 1), (25, 25, 2), (75, 70, 7), (80, 75, 8), (100, 75, 8)])
def test_mixed_modules_share_budget_and_deduplicate_per_module(sqlite_app, budget, used, analyses):
    before = sqlite_app.server.database.manifest()
    report = run_scan(sqlite_app.url + "/combined-lab", modules=("sqli", "xss", "xss"), max_requests=budget, interval=0)
    assert len(report.requests) == used <= budget
    assert len(report.analyses) == analyses
    assert len({(target["url"], target["parameter"], target["module"]) for target in report.targets}) == len(report.targets) == 8
    assert [entry["request_id"] for entry in report.requests] == list(range(1, used + 1))
    assert before == sqlite_app.server.database.manifest()
    if budget >= 80:
        assert report.status == "completed"
        results = report.to_dict()["parameter_results"]
        assert {result["module"] for result in results} == {"sqli", "xss"}
        assert any(result["module"] == "sqli" and result["assessment"]["outcome"] == "confirmed" for result in results)


@pytest.mark.skipif(not HAS_BROWSER, reason="Confirmação opcional requer navegador local e Node.")
def test_browser_replays_do_not_contact_target_or_another_local_port(http_lab):
    sink = http_lab.start(lambda _: http_lab.reply())
    def respond(request):
        body = f'<img src="{sink.url}/image"><script>fetch("{sink.url}/blocked");</script><p>{request.query["q"][0]}</p>'
        return http_lab.reply(body=body.encode(), headers={"Content-Type": "text/html"})
    site = http_lab.start(respond)
    report = run_xss(site.url + "?q=demo", interval=0, browser=True)
    assert report.assessment.outcome == "confirmed"
    assert len(site.calls) == len(report.responses) == 10
    assert sink.calls == []
    assert report.assessment.browser_evidence["target_network_requests"] == 0


def test_missing_browser_keeps_real_static_evidence_as_suspicion(sqlite_app, monkeypatch):
    monkeypatch.setattr("scanner.xss_browser.browser_path", lambda: None)
    report = run_xss(sqlite_app.url + "/xss/html/raw?q=demo", interval=0, browser=True)
    assert report.assessment.outcome == "suspected"
    assert report.assessment.browser_evidence["status"] == "unavailable"
    assert all(finding.status == "suspected" for finding in report.findings)


def test_redirects_are_not_followed_and_cannot_confirm_xss(http_lab):
    sink = http_lab.start(lambda _: http_lab.reply())
    site = http_lab.start(lambda request: http_lab.reply(status=302, headers={"Location": sink.url})
                          if request.query["q"] != ["demo"] else http_lab.reply(body=b"ready", headers={"Content-Type": "text/html"}))
    report = run_xss(site.url + "?q=demo", interval=0)
    assert report.assessment.outcome == "inconclusive"
    assert sink.calls == [] and not report.findings


@pytest.mark.parametrize("url,options", [
    ("http://localhost/echo?q=demo", {"samples": 1}),
    ("http://localhost/echo?q=demo", {"max_requests": 9}),
    ("http://localhost/echo?q=demo", {"parameter": "missing"}),
    ("http://localhost/echo?q=demo&q=other", {}),
    ("http://example.invalid/echo?q=demo", {}),
])
def test_invalid_xss_configuration_is_rejected_before_network(url, options, monkeypatch):
    send = Mock()
    monkeypatch.setattr(requests.Session, "get", send)
    with pytest.raises(ValueError):
        run_xss(url, **options)
    send.assert_not_called()


def test_cli_xss_and_combined_scan_export_separate_module_results(sqlite_app, tmp_path):
    def invoke(*arguments):
        return subprocess.run([sys.executable, str(ROOT / "main.py"), *arguments], cwd=tmp_path,
                              env={**os.environ, "PYTHONUTF8": "1"}, capture_output=True,
                              text=True, encoding="utf-8", timeout=30)
    direct = tmp_path / "xss.json"
    result = invoke(sqlite_app.url + "/xss/json?q=demo", "--module", "xss", "--interval", "0", "--output", str(direct))
    assert result.returncode == 0, result.stderr
    assert "XSS: reflected_safe" in result.stdout
    data = json.loads(direct.read_text(encoding="utf-8"))
    assert data["mode"] == "xss" and data["findings"] == []
    combined = tmp_path / "combined.json"
    result = invoke("scan", sqlite_app.url + "/combined-lab", "--modules", "sqli", "xss", "--interval", "0", "--output", str(combined))
    assert result.returncode == 0, result.stderr
    data = json.loads(combined.read_text(encoding="utf-8"))
    assert data["summary"]["requests_used"] == 75
    assert {result["module"] for result in data["parameter_results"]} == {"xss", "sqli"}


def test_xss_scan_interruption_preserves_partial_report(sqlite_app, monkeypatch, tmp_path):
    original, calls = requests.Session.get, 0
    def interrupt(session, *args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 4:
            raise KeyboardInterrupt
        return original(session, *args, **kwargs)
    monkeypatch.setattr(requests.Session, "get", interrupt)
    output = tmp_path / "partial.json"
    report = run_scan(sqlite_app.url + "/xss/html/raw?q=demo", modules=("xss",), interval=0,
                      checkpoint=lambda current: write_json_atomic(current, output))
    assert report.status == "interrupted" and len(report.requests) == 4
    assert report.analyses[0].assessment.outcome == "inconclusive"
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["status"] == "interrupted"


def test_browser_option_requires_xss_before_network(monkeypatch):
    send = Mock()
    monkeypatch.setattr(requests.Session, "get", send)
    for arguments in (["http://localhost/?q=demo", "--module", "sqli", "--xss-browser"],
                      ["scan", "http://localhost/", "--xss-browser"]):
        with pytest.raises(SystemExit) as failure:
            main(arguments)
        assert failure.value.code == 2
    send.assert_not_called()
