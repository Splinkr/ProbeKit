"""R02: coleta e avaliações individuais permanecem distintas no JSON."""

from dataclasses import asdict

import pytest

from scanner.discovery import new_discovery_report
from scanner.exposure_models import ExposureAssessment, ExposureReport, ExposureResult
from scanner.findings_report import build_findings_report
from scanner.models import (Confidence, Finding, FindingStatus, IntegratedScanReport,
                            ParameterResult, ScanReport, SqliAssessment)


OUTCOMES = ("confirmed", "suspected", "not_detected", "reflected_safe", "inconclusive")


def direct(outcomes):
    report = ScanReport("http://127.0.0.1/?q=demo", "start", {}, mode="sqli", finished_at="finish")
    for index, outcome in enumerate(outcomes):
        assessment = SqliAssessment(outcome, {}, "fixture", [], f"q{index}")
        report.parameter_results.append(ParameterResult(f"q{index}", "like", assessment, []))
    report.assessment = report.parameter_results[0].assessment if outcomes else None
    return report


@pytest.mark.parametrize("outcomes", [["inconclusive"], ["confirmed", "inconclusive"], list(OUTCOMES)])
def test_direct_summary_separates_collection_from_analysis_without_double_counting(outcomes):
    report = direct(outcomes)
    data = report.to_dict()
    summary = build_findings_report(data, "full.json")
    assert data["summary"]["status"] == summary["scan_status"] == "completed"
    assert data["collection_status"] == summary["collection_status"] == "completed"
    expected = {"applicable": True, "evaluations": len(outcomes),
                "outcomes": {name: outcomes.count(name) for name in OUTCOMES},
                "has_inconclusive": "inconclusive" in outcomes}
    assert data["analysis_summary"] == summary["analysis_summary"] == expected


def test_inconclusive_with_no_findings_is_visible_in_the_findings_report():
    summary = build_findings_report(direct(["inconclusive"]).to_dict(), "full.json")
    assert summary["findings"] == []
    assert summary["summary"]["confirmed"] == 0
    assert summary["analysis_summary"]["has_inconclusive"]


def test_confirmed_finding_survives_another_inconclusive_evaluation():
    report = direct(["confirmed", "inconclusive"])
    report.findings.append(Finding(report.target, "sqli", "fixture", Confidence.HIGH,
        FindingStatus.CONFIRMED, [1], "fixture", "fixture", "fixture", "q0"))
    summary = build_findings_report(report.to_dict(), "full.json")
    assert summary["summary"]["confirmed"] == 1
    assert summary["findings"][0]["status"] == "confirmed"
    assert summary["analysis_summary"]["outcomes"]["inconclusive"] == 1


def test_integrated_legacy_status_is_preserved_but_collection_is_independent():
    discovery = new_discovery_report("http://127.0.0.1/")
    discovery.finished_at = "finish"
    report = IntegratedScanReport(discovery.target, "start", {"max_requests": 100, "modules": ["sqli"]},
                                  discovery, analyses=[direct(["confirmed", "inconclusive"])],
                                  status="incomplete", finished_at="finish")
    data = report.to_dict()
    assert data["summary"]["status"] == "incomplete"
    assert data["collection_status"] == "completed"
    assert data["analysis_summary"]["evaluations"] == 2
    assert build_findings_report(data, "full.json")["analysis_summary"] == data["analysis_summary"]


def test_exposure_individual_results_take_precedence_over_aggregate():
    assessment = ExposureAssessment("inconclusive", {}, "fixture", [])
    report = ExposureReport("http://127.0.0.1/", "start", {}, assessment=assessment, finished_at="finish")
    report.exposure_results.append(ExposureResult(report.target + ".env", "config", "dotenv", assessment, []))
    data = report.to_dict()
    assert data["collection_status"] == "completed"
    assert data["analysis_summary"]["evaluations"] == 1
    assert data["analysis_summary"]["outcomes"]["inconclusive"] == 1


@pytest.mark.parametrize("mode", ["baseline", "discover", "sqli", "xss", "exposure", "scan"])
def test_empty_reports_and_legacy_inputs_are_supported(mode):
    data = {"mode": mode}
    result = build_findings_report(data, "legacy.json")
    assert result["collection_status"] is None
    assert result["analysis_summary"] == {
        "applicable": mode not in {"baseline", "discover"}, "evaluations": 0,
        "outcomes": dict.fromkeys(OUTCOMES, 0), "has_inconclusive": False,
    }
    assert result["schema_version"] == "1.0"


def test_legacy_aggregate_is_used_only_when_individual_results_are_absent():
    assessment = SqliAssessment("inconclusive", {}, "fixture", [])
    result = build_findings_report({"mode": "sqli", "assessment": asdict(assessment)}, "legacy.json")
    assert result["analysis_summary"]["evaluations"] == 1
    assert result["analysis_summary"]["has_inconclusive"]


def test_baseline_and_discovery_have_no_analytic_evaluations():
    baseline = ScanReport("http://127.0.0.1/", "start", {}, finished_at="finish")
    discovery = new_discovery_report(baseline.target)
    discovery.finished_at = "finish"
    for report in (baseline, discovery):
        data = report.to_dict()
        assert data["collection_status"] == "completed"
        assert not data["analysis_summary"]["applicable"]
        assert data["analysis_summary"]["evaluations"] == 0


@pytest.mark.parametrize("prefix,legacy_status", [([], "completed"), (["scan"], "incomplete")])
def test_real_inconclusive_sqli_collection_is_completed_in_both_cli_modes(sqlite_app, tmp_path, prefix, legacy_status):
    import json
    from main import main

    output = tmp_path / "report.json"
    assert main([*prefix, sqlite_app.url + "/general/html/error?search=apple", "--interval", "0", "--output", str(output),
                 *([] if prefix else ["--module", "sqli"])]) == 1
    data = json.loads(output.read_text(encoding="utf-8"))
    findings = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert data["summary"]["status"] == findings["scan_status"] == legacy_status
    assert data["collection_status"] == findings["collection_status"] == "completed"
    assert findings["analysis_summary"]["outcomes"]["inconclusive"] == 1
    assert findings["findings"] == []


@pytest.mark.parametrize("module,expected", [("sqli", 1), ("xss", 1), ("exposure", 2)])
def test_http_responses_without_transport_errors_can_be_analytically_inconclusive(http_lab, tmp_path, module, expected):
    import json
    from main import main

    site = http_lab.start(lambda _: http_lab.reply(status=302))
    output = tmp_path / "report.json"
    url = site.url + ("/" if module == "exposure" else "/?q=apple")
    assert main([url, "--module", module, "--interval", "0", "--output", str(output)]) == 1
    data = json.loads(output.read_text(encoding="utf-8"))
    summary = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert data["errors"] == data["execution_errors"] == []
    assert summary["collection_status"] == summary["scan_status"] == "completed"
    assert summary["analysis_summary"]["outcomes"]["inconclusive"] == expected
