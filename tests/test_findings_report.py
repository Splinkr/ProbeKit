"""Resumo de achados: projeção fiel, privacidade, checkpoints e CLI real."""

from copy import deepcopy
import json
import shutil
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from experiments import exposure_lab
from main import main
from scanner.findings_report import build_findings_report
from scanner.models import Confidence, Finding, FindingStatus, ScanReport
from scanner.reporter import findings_path, write_reports
from scanner.xss_browser import browser_path


def finding(module="sqli", status="confirmed", **overrides):
    return {
        "endpoint": "http://127.0.0.1/search?term=apple&lang=en",
        "category": module, "title": "Fixture de apresentação",
        "confidence": "high" if status == "confirmed" else "low", "status": status,
        "evidence_request_ids": [3, 1, 3], "rationale": "Evidência calculada pelo detector.",
        "potential_impact": "Impacto já descrito pelo módulo.",
        "recommended_mitigation": "Mitigação já descrita pelo módulo.",
        "parameter": "term", **overrides,
    }


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_only_security_findings_are_projected_without_reclassifying_or_mutating_data():
    data = {"mode": "scan", "summary": {"status": "limited"}, "analyses": [
        {"mode": module, "findings": [finding(module, status) for status in
         ("confirmed", "suspected", "inconclusive", "not_detected", "reflected_safe")]}
        for module in ("sqli", "xss", "exposure")
    ], "parameter_results": [{"assessment": {"outcome": "confirmed"}}]}
    # A cópia consolidada não é outra fonte de achados.
    data["findings"] = [finding()]
    before = deepcopy(data)
    summary = build_findings_report(data, "full.json")
    assert data == before
    assert summary["scan_status"] == "limited"
    assert summary["source_report"] == "full.json"
    assert summary["summary"] == {
        "total": 6, "confirmed": 3, "suspected": 3,
        "by_module": {module: {"total": 2, "confirmed": 1, "suspected": 1}
                      for module in ("sqli", "xss", "exposure")},
    }
    assert {item["vulnerability_type"] for item in summary["findings"]} == {
        "sql_injection", "reflected_xss", "sensitive_file_exposure"}
    for item in summary["findings"]:
        assert item["url"] == finding()["endpoint"] and not item["url_redacted"]
        assert item["parameter"] == "term"
        assert item["confidence"] == ("high" if item["status"] == "confirmed" else "low")
        assert item["evidence_request_ids"] == [1, 3]
        assert item["evidence"] == finding()["rationale"]
        assert item["potential_impact"] == finding()["potential_impact"]
        assert item["recommended_mitigation"] == finding()["recommended_mitigation"]


def test_duplicates_merge_evidence_without_collapsing_modules_parameters_or_urls():
    data = {"mode": "sqli", "findings": [
        finding(), finding(evidence_request_ids=[2, 3]),
        finding(parameter="lang"), finding("xss"),
        finding(endpoint="http://127.0.0.1/search?term=orange&lang=en"),
    ]}
    result = build_findings_report(data, "full.json")
    assert result["summary"]["total"] == 4
    assert result["findings"][0]["evidence_request_ids"] == [1, 2, 3]


def test_absent_optional_confidence_and_parameter_remain_null():
    item = finding("exposure", endpoint="http://127.0.0.1/.env", parameter=None)
    del item["confidence"]
    result = build_findings_report({"findings": [item]}, "full.json")["findings"][0]
    assert result["confidence"] is None and result["parameter"] is None


@pytest.mark.parametrize("mode", ["baseline", "discover", "sqli", "xss", "exposure", "scan"])
def test_no_findings_is_valid_json_with_zero_counts(mode):
    summary = build_findings_report({"mode": mode}, "full.json")
    assert json.loads(json.dumps(summary))["findings"] == []
    assert summary["summary"]["total"] == summary["summary"]["confirmed"] == summary["summary"]["suspected"] == 0
    assert all(counts == {"total": 0, "confirmed": 0, "suspected": 0}
               for counts in summary["summary"]["by_module"].values())


@pytest.mark.parametrize("secret_name", [
    "password", "db_password", "access_token", "apiKey", "%61pi_key", "sessionid",
    "Authorization", "cookie", "client_secret", "credentials", "private-key", "jwt", "key",
])
def test_credentials_and_sensitive_query_values_are_redacted(secret_name):
    data = {"findings": [finding(endpoint=(
        "http://private-user:private-pass@127.0.0.1:8005/search?term=apple&"
        f"{secret_name}=private-query-value&lang=en#private-fragment"
    ), body="private-body", headers={"Set-Cookie": "private-cookie"})],
        "responses": [{"body": "private-body", "headers": {"Authorization": "private-auth"}}]}
    before = deepcopy(data)
    result = build_findings_report(data, "full.json")
    raw = json.dumps(result)
    assert not any(value in raw for value in (
        "private-user", "private-pass", "private-query-value", "private-fragment",
        "private-body", "private-cookie", "private-auth"))
    assert data == before
    item = result["findings"][0]
    assert item["url_redacted"]
    parts = urlsplit(item["url"])
    assert parts.netloc == "127.0.0.1:8005" and not parts.fragment
    query = parse_qs(parts.query)
    assert query["term"] == ["apple"] and query["lang"] == ["en"]
    assert "[REDACTED]" in [value[0] for value in query.values()]
    assert set(item) == {
        "module", "vulnerability_type", "url", "url_redacted", "parameter", "status",
        "confidence", "evidence", "evidence_request_ids", "potential_impact", "recommended_mitigation",
    }


@pytest.mark.parametrize("atomic", [False, True])
def test_writing_both_reports_preserves_the_full_snapshot_and_never_contacts_network(tmp_path, monkeypatch, atomic):
    report = ScanReport("http://127.0.0.1/search?term=apple", "fixture", {}, mode="sqli")
    report.findings.append(Finding(
        report.target, "sqli", "Fixture", Confidence.HIGH, FindingStatus.CONFIRMED,
        [1, 2], "Evidência existente.", "Impacto existente.", "Mitigação existente.", "term"))
    before = report.to_dict()
    snapshot = Mock(return_value=before)
    monkeypatch.setattr(report, "to_dict", snapshot)
    send = Mock(side_effect=AssertionError("Relatórios não devem acessar a rede"))
    monkeypatch.setattr(requests.Session, "request", send)
    output = tmp_path / "nested" / "full.json"
    assert write_reports(report, output, atomic=atomic) == output
    assert load(output) == before
    summary = load(output.with_name("findings.json"))
    assert summary["findings"][0]["evidence"] == before["findings"][0]["rationale"]
    assert summary["summary"]["total"] == 1
    snapshot.assert_called_once_with()
    send.assert_not_called()
    assert not list(output.parent.glob(".scan-*.tmp"))


@pytest.mark.parametrize("browser", [False, pytest.param(True, marks=pytest.mark.skipif(
    not (browser_path() and shutil.which("node")), reason="Requer navegador local e Node."))])
def test_real_three_module_cli_keeps_evidence_ids_statuses_and_request_count(sqlite_app, tmp_path, monkeypatch, capsys, browser):
    sent = []
    original = requests.Session.get

    def get(session, url, *args, **kwargs):
        sent.append(url)
        return original(session, url, *args, **kwargs)

    monkeypatch.setattr(requests.Session, "get", get)
    output = tmp_path / "full.json"
    arguments = ["scan", sqlite_app.url + "/probekit-lab", "--modules", "sqli", "xss", "exposure",
                 "--exposure-profiles", "config", "backup", "--interval", "0", "--output", str(output)]
    if browser:
        arguments.append("--xss-browser")
    assert main(arguments) == 0
    full, summary = load(output), load(tmp_path / "findings.json")
    assert "Achados JSON:" in capsys.readouterr().out
    assert full["summary"]["requests_used"] == len(sent) == 92
    assert summary["scan_status"] == "completed"
    assert summary["summary"]["total"] == 4
    assert summary["summary"]["by_module"] == {
        "sqli": {"total": 1, "confirmed": 1, "suspected": 0},
        "xss": {"total": 1, "confirmed": int(browser), "suspected": int(not browser)},
        "exposure": {"total": 2, "confirmed": 2, "suspected": 0},
    }
    original_findings = [item for analysis in full["analyses"] for item in analysis["findings"]]
    for item, source in zip(summary["findings"], original_findings, strict=True):
        assert item["url"] == source["endpoint"]
        assert item["status"] == source["status"] and item["confidence"] == source["confidence"]
        assert item["evidence"] == source["rationale"]
        assert item["evidence_request_ids"] == source["evidence_request_ids"]
        assert set(item["evidence_request_ids"]) <= {request["request_id"] for request in full["requests"]}
    assert not any(value in json.dumps(summary) for value in exposure_lab.SENTINELS)


@pytest.mark.parametrize("prefix", [[], ["discover"]])
def test_baseline_and_discovery_cli_also_write_empty_summary(http_lab, tmp_path, prefix):
    site = http_lab.start(lambda _: http_lab.reply())
    output = tmp_path / "full.json"
    assert main([*prefix, site.url, "--interval", "0", "--output", str(output)]) == 0
    assert load(tmp_path / "findings.json")["findings"] == []


def test_direct_module_cli_writes_suspected_findings(sqlite_app, tmp_path):
    output = tmp_path / "full.json"
    assert main([sqlite_app.url + "/xss/html/raw?q=demo", "--module", "xss", "--interval", "0",
                 "--output", str(output)]) == 0
    assert load(tmp_path / "findings.json")["findings"][0]["status"] == "suspected"


@pytest.mark.parametrize("budget,expected", [(1, 0), (84, 3)])
def test_limited_scan_does_not_report_skipped_targets_as_findings(sqlite_app, tmp_path, budget, expected):
    output = tmp_path / "full.json"
    assert main(["scan", sqlite_app.url + "/probekit-lab", "--modules", "sqli", "xss", "exposure",
                 "--exposure-profiles", "config", "backup", "--max-requests", str(budget),
                 "--interval", "0", "--output", str(output)]) == 0
    summary = load(tmp_path / "findings.json")
    assert summary["scan_status"] == "limited"
    assert summary["summary"]["total"] == len(summary["findings"]) == expected


@pytest.mark.parametrize("name", ["findings.json", "FINDINGS.JSON"])
def test_output_named_findings_does_not_overwrite_the_technical_report(http_lab, tmp_path, name):
    site = http_lab.start(lambda _: http_lab.reply())
    output = tmp_path / name
    assert main([site.url, "--interval", "0", "--output", str(output)]) == 0
    assert load(output)["mode"] == "baseline"
    assert findings_path(output) == tmp_path / "findings-summary.json"
    assert load(findings_path(output))["report_type"] == "security_findings"


def test_later_execution_replaces_prior_findings_with_empty_list(sqlite_app, tmp_path):
    output = tmp_path / "full.json"
    for route, expected in (("vulnerable", 1), ("safe", 0)):
        assert main([sqlite_app.url + f"/general/json/{route}?term=apple", "--module", "sqli",
                     "--interval", "0", "--output", str(output)]) == 0
        summary = load(tmp_path / "findings.json")
        assert summary["summary"]["total"] == len(summary["findings"]) == expected


def test_interrupted_scan_keeps_summary_of_completed_findings(sqlite_app, tmp_path, monkeypatch):
    original = requests.Session.get
    sent = 0

    def get(session, *args, **kwargs):
        nonlocal sent
        sent += 1
        if sent == 29:
            raise KeyboardInterrupt
        return original(session, *args, **kwargs)

    monkeypatch.setattr(requests.Session, "get", get)
    output = tmp_path / "full.json"
    assert main(["scan", sqlite_app.url + "/probekit-lab", "--modules", "sqli", "xss", "exposure",
                 "--interval", "0", "--output", str(output)]) == 130
    full, summary = load(output), load(tmp_path / "findings.json")
    assert full["summary"]["status"] == summary["scan_status"] == "interrupted"
    assert summary["summary"]["total"] == 1
    assert summary["findings"][0]["module"] == "xss"
    assert summary["findings"][0]["status"] == "suspected"


def test_unwritable_summary_preserves_full_report_and_fails_before_scan_network(http_lab, tmp_path, capsys):
    site = http_lab.start(lambda _: http_lab.reply())
    (tmp_path / "findings.json").mkdir()
    output = tmp_path / "full.json"
    assert main(["scan", site.url, "--output", str(output)]) == 1
    assert load(output)["mode"] == "scan"
    assert site.calls == []
    assert "Erro ao gravar relatório consolidado" in capsys.readouterr().err
    assert not list(tmp_path.glob(".scan-*.tmp"))
