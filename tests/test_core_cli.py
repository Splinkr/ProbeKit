from dataclasses import replace
import hashlib
import json
from unittest.mock import Mock

import pytest

from main import main
from scanner.analyzer import compare_responses
from scanner.core import run_baseline
from scanner.models import Confidence, Finding, FindingStatus, ResponseEvidence
from scanner.reporter import write_json


def test_reference_report_excludes_bodies_and_secrets(local_server, tmp_path):
    base, _ = local_server
    report = run_baseline(base + "/stable", samples=3, interval=0)
    output = write_json(report, tmp_path / "nested" / "report.json")
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["summary"] == {
        "reachable": True, "status": "completed", "requests_attempted": 3,
        "responses_received": 3, "errors": 0, "findings": 0,
    }
    assert len(data["comparisons"]) == 2
    assert all(not comparison["body_changed"] for comparison in data["comparisons"])
    assert data["findings"] == []
    assert data["finished_at"] is not None
    assert "reference body" not in output.read_text(encoding="utf-8")
    assert "do-not-persist" not in output.read_text(encoding="utf-8")
    assert "body" not in data["responses"][0]


def test_changed_response_does_not_create_finding(local_server):
    base, _ = local_server
    report = run_baseline(base + "/changing", interval=0)
    assert report.comparisons[0].body_changed
    assert report.comparisons[0].size_delta_bytes == 0
    assert report.findings == []


def test_analyzer_covers_status_type_size_and_full_body_hash():
    body = b"a" * 17_000
    baseline = ResponseEvidence(1, "http://127.0.0.1/", "now", 200, "text/plain",
                                len(body), hashlib.sha256(body).hexdigest(), 1.0, body)
    changed_body = body + b"b"
    current = replace(baseline, request_id=2, status_code=500, content_type="application/json",
                      size_bytes=len(changed_body), body=changed_body,
                      body_sha256=hashlib.sha256(changed_body).hexdigest())
    result = compare_responses(baseline, current)
    assert result.body_changed and result.status_changed and result.content_type_changed
    assert result.size_delta_bytes == 1
    assert result.sample_similarity == 1.0  # Alteração fora dos 16 KiB da amostra.
    assert result.compared_sample_bytes == 16_384


def test_failure_stops_scan_and_still_writes_json(local_server, tmp_path):
    base, state = local_server
    output = tmp_path / "failure.json"
    assert main([base + "/large", "--max-body-bytes", "10", "--output", str(output)]) == 1
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["errors"][0]["kind"] == "response_too_large"
    assert data["summary"]["status"] == "incomplete"
    assert len(state["requests"]) == 1


def test_cli_success(local_server, tmp_path, capsys):
    base, _ = local_server
    output = tmp_path / "success.json"
    assert main([base + "/json", "--output", str(output), "--interval", "0"]) == 0
    assert "Conectividade HTTP: OK" in capsys.readouterr().out
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["responses_received"] == 2


@pytest.mark.parametrize("arguments", [
    ["http://example.com"], ["http://127.0.0.1", "--samples", "0"],
    ["http://127.0.0.1", "--timeout", "nan"],
    ["http://127.0.0.1", "--timeout", "inf"],
    ["http://127.0.0.1", "--interval", "-1"],
    ["http://127.0.0.1", "--samples", "3", "--max-requests", "2"],
])
def test_invalid_cli_never_sends_requests(arguments, monkeypatch):
    request = Mock()
    monkeypatch.setattr("requests.Session.get", request)
    with pytest.raises(SystemExit) as raised:
        main(arguments)
    assert raised.value.code == 2
    request.assert_not_called()


def test_write_error_has_nonzero_exit(local_server, tmp_path, capsys):
    base, _ = local_server
    assert main([base, "--samples", "1", "--output", str(tmp_path)]) == 1
    assert "Erro ao gravar relatório" in capsys.readouterr().err


def test_finding_contract_serializes_with_evidence(local_server):
    base, _ = local_server
    report = run_baseline(base, samples=1)
    report.findings.append(Finding(
        endpoint=base, category="test_fixture", title="Achado simulado pelo teste",
        confidence=Confidence.LOW, status=FindingStatus.SUSPECTED,
        evidence_request_ids=[1], rationale="Contrato de serialização.",
        potential_impact="Não avaliado.", recommended_mitigation="Não aplicável ao teste.",
    ))
    data = json.loads(json.dumps(report.to_dict()))
    assert data["findings"][0]["evidence_request_ids"] == [1]
    assert data["findings"][0]["status"] == "suspected"
