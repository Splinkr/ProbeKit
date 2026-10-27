"""Apresentação dos estados reais do contrato; fixtures de classificação não são scans."""

import json
import pytest
import requests

from main import main
from scanner.discovery import new_discovery_report
from scanner.exposure_models import ExposureAssessment, ExposureReport, ExposureResult
from scanner.models import IntegratedScanReport, ParameterResult, ScanReport, SqliAssessment, XssAssessment
from scanner.terminal import format_scan_results


def sample_report(outcomes):
    report = IntegratedScanReport("http://127.0.0.1/", "fixture", {"modules": ["sqli", "xss", "exposure"], "max_requests": 100},
                                  new_discovery_report("http://127.0.0.1/"), status="completed")
    for index, (module, outcome) in enumerate(outcomes):
        url = f"http://127.0.0.1/item{index}?q=demo"
        if module == "exposure":
            assessment = ExposureAssessment(outcome, {}, "Fixture de apresentação", [])
            analysis = ExposureReport(url, "fixture", {}, assessment=assessment)
            analysis.exposure_results.append(ExposureResult(url, "config", "dotenv", assessment, []))
        else:
            assessment = (XssAssessment if module == "xss" else SqliAssessment)(outcome, {}, "Fixture de apresentação", [], "q")
            analysis = ScanReport(url, "fixture", {}, mode=module, assessment=assessment)
            analysis.parameter_results.append(ParameterResult("q", assessment.context, assessment, []))
        report.analyses.append(analysis)
        report.targets.append({"module": module, "url": url, "status": "completed"})
    if any(outcome == "inconclusive" for _, outcome in outcomes):
        report.status = "incomplete"
    return report


def table_row(output, module):
    return next(line.split() for line in output.splitlines() if line.split() and line.split()[0] == module)


def test_summary_keeps_all_five_outcomes_separate_without_mutating_report():
    report = sample_report([("sqli", "confirmed"), ("sqli", "suspected"), ("sqli", "inconclusive"),
                            ("xss", "reflected_safe"), ("xss", "not_detected"), ("exposure", "confirmed")])
    before = report.to_dict()
    output = format_scan_results(report)
    assert table_row(output, "sqli") == ["sqli", "1", "1", "1", "0", "0"]
    assert table_row(output, "xss") == ["xss", "0", "0", "0", "1", "1"]
    assert table_row(output, "exposure") == ["exposure", "1", "0", "0", "0", "0"]
    assert table_row(output, "TOTAL") == ["TOTAL", "2", "1", "1", "1", "1"]
    assert "Avaliações classificadas: 6" in output
    assert report.to_dict() == before


@pytest.mark.parametrize("module,outcome,expected,exit_code", [
    ("sqli", "confirmed", ["1", "0", "0", "0", "0"], 0),
    ("sqli", "suspected", ["0", "1", "0", "0", "0"], 0),
    ("sqli", "inconclusive", ["0", "0", "1", "0", "0"], 1),
    ("exposure", "not_detected", ["0", "0", "0", "1", "0"], 0),
    ("xss", "reflected_safe", ["0", "0", "0", "0", "1"], 0),
])
def test_cli_table_and_json_preserve_each_outcome(monkeypatch, capsys, tmp_path, module, outcome, expected, exit_code):
    report = sample_report([(module, outcome)])
    before = report.to_dict()
    output = tmp_path / "scan.json"

    def run(url, **settings):
        settings["checkpoint"](report)
        return report

    monkeypatch.setattr("main.run_scan", run)
    assert main(["scan", report.target, "--modules", module, "--output", str(output)]) == exit_code
    terminal = capsys.readouterr().out
    assert table_row(terminal, module)[1:] == expected
    assert f": {outcome}" in terminal
    assert json.loads(output.read_text(encoding="utf-8")) == before == report.to_dict()
    assert terminal.index("Resumo do scan") < terminal.index("Relatório consolidado JSON:")


def test_skipped_targets_and_unclassified_analysis_are_not_negative_results():
    report = sample_report([])
    report.targets.extend([{"status": "skipped"}, {"status": "interrupted"}, {"status": "pending"}])
    report.analyses.append(ScanReport(report.target, "fixture", {}, mode="xss"))
    output = format_scan_results(report)
    assert table_row(output, "TOTAL")[1:] == ["0", "0", "0", "0", "0"]
    assert "Alvos planejados não concluídos: 3; análises sem classificação: 1" in output
    assert "Nenhuma avaliação classificada" in output
    assert "não garantem ausência" in output


def test_real_three_module_cli_summary_matches_saved_json(sqlite_app, tmp_path, capsys):
    output = tmp_path / "scan.json"
    assert main(["scan", sqlite_app.url + "/probekit-lab", "--modules", "sqli", "xss", "exposure",
                 "--exposure-profiles", "config", "backup", "--interval", "0", "--output", str(output)]) == 0
    terminal = capsys.readouterr().out
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["summary"]["requests_used"] == 92
    assert table_row(terminal, "sqli")[1:] == ["1", "0", "0", "3", "0"]
    assert table_row(terminal, "xss")[1:] == ["0", "1", "0", "2", "1"]
    assert table_row(terminal, "exposure")[1:] == ["2", "0", "0", "2", "0"]
    assert "Avaliações classificadas: 12" in terminal
    assert all(value not in terminal for value in ("EXPOSURE_FAKE_CONFIG_7319", "EXPOSURE_FAKE_BACKUP_9531"))


def test_real_inconclusive_scan_stays_inconclusive_in_terminal(sqlite_app, tmp_path, capsys):
    output = tmp_path / "scan.json"
    assert main(["scan", sqlite_app.url + "/general/html/error?search=apple", "--interval", "0", "--output", str(output)]) == 1
    terminal = capsys.readouterr().out
    assert table_row(terminal, "sqli")[1:] == ["0", "0", "1", "0", "0"]
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["status"] == "incomplete"


def test_interrupt_before_classification_keeps_zero_counts_and_checkpoint(sqlite_app, monkeypatch, tmp_path, capsys):
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(requests.Session, "get", interrupt)
    output = tmp_path / "interrupted.json"
    assert main(["scan", sqlite_app.url + "/probekit-lab", "--output", str(output)]) == 130
    terminal = capsys.readouterr().out
    assert table_row(terminal, "TOTAL")[1:] == ["0", "0", "0", "0", "0"]
    assert "Nenhuma avaliação classificada" in terminal
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["status"] == "interrupted"
