"""Comparação e persistência não podem transformar diferenças em achados."""

from dataclasses import replace
import hashlib
import json

import pytest

from scanner.analyzer import compare_responses
from scanner.core import run_baseline
from scanner.models import Confidence, Finding, FindingStatus, ResponseEvidence, ScanReport, utc_now
from scanner.reporter import write_json


def response(body: bytes, request_id=1):
    return ResponseEvidence(
        request_id=request_id, url="http://127.0.0.1/", collected_at=utc_now(),
        status_code=200, content_type="text/plain", size_bytes=len(body),
        body_sha256=hashlib.sha256(body).hexdigest(), elapsed_ms=0, body=body,
    )


@pytest.mark.parametrize("original,changed", [(b"", b""), (b"same", b"same"), (b"one", b"two")])
def test_body_equality_is_independent_of_request_identity(original, changed):
    result = compare_responses(response(original), response(changed, 2))
    assert result.body_changed == (original != changed)
    assert result.size_delta_bytes == len(changed) - len(original)
    assert not result.status_changed
    assert (result.baseline_request_id, result.compared_request_id) == (1, 2)


def test_change_outside_similarity_sample_is_still_visible():
    original = response(b"a" * 20_000)
    current = replace(response(b"a" * 20_000 + b"b", 2), status_code=503, content_type="application/json")
    result = compare_responses(original, current)
    assert result.sample_similarity == 1
    assert result.compared_sample_bytes == 16_384
    assert result.body_changed and result.status_changed and result.content_type_changed
    assert result.size_delta_bytes == 1


def test_baseline_retains_observations_without_inventing_findings(http_lab, tmp_path):
    origin = http_lab.start(lambda request: http_lab.reply(body=f"dynamic {request.number}".encode()))
    report = run_baseline(origin.url, samples=3, interval=0)
    data = json.loads(write_json(report, tmp_path / "result.json").read_text(encoding="utf-8"))
    assert data["mode"] == "baseline"
    assert data["summary"]["requests_attempted"] == 3
    assert len(data["comparisons"]) == 2
    assert all(item["body_changed"] for item in data["comparisons"])
    assert data["findings"] == []
    assert data["finished_at"] >= data["started_at"]


def test_transport_failure_keeps_prior_evidence_and_stops_further_requests(http_lab):
    origin = http_lab.start(lambda call: http_lab.reply(body=b"ok" if call.number == 1 else b"x" * 100))
    report = run_baseline(origin.url, samples=4, interval=0, max_body_bytes=10)
    assert len(origin.calls) == 2
    assert len(report.responses) == len(report.errors) == 1
    assert report.responses[0].request_id == 1
    assert report.errors[0].request_id == 2
    assert report.to_dict()["summary"]["status"] == "incomplete"


def test_json_does_not_persist_body_cookies_or_server_secrets(http_lab, tmp_path):
    origin = http_lab.start(lambda _: http_lab.reply(
        body=b"private-body-value", headers={"Set-Cookie": "token=private-cookie-value"}
    ))
    report = run_baseline(origin.url, interval=0)
    output = write_json(report, tmp_path / "nested" / "evidence.json")
    raw = output.read_text(encoding="utf-8")
    data = json.loads(raw)
    assert "private-body-value" not in raw and "private-cookie-value" not in raw
    assert all("body" not in item for item in data["responses"])
    assert data["responses"][0]["body_sha256"] == hashlib.sha256(b"private-body-value").hexdigest()


def test_finding_metadata_round_trips_without_enum_or_encoding_loss(tmp_path):
    report = ScanReport(target="http://127.0.0.1/", started_at=utc_now(), settings={})
    report.findings.append(Finding(
        endpoint=report.target, category="unit_fixture", title="Evidência sintética de serialização",
        confidence=Confidence.LOW, status=FindingStatus.SUSPECTED, evidence_request_ids=[],
        rationale="Somente teste unitário.", potential_impact="Não avaliado.", recommended_mitigation="Não aplicável.",
    ))
    output = write_json(report, tmp_path / "finding.json")
    finding = json.loads(output.read_text(encoding="utf-8"))["findings"][0]
    assert finding["status"] == "suspected" and finding["confidence"] == "low"
    assert finding["title"] == report.findings[0].title
