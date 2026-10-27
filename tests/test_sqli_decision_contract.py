"""Decisões puras sobre evidências sintéticas; não são resultados empíricos."""

from dataclasses import replace
import json

import pytest

from scanner.models import ProbeEvidence, ResponseEvidence, ScanReport, utc_now
from scanner.modules.sqli import assess, observe


@pytest.fixture
def decision_report():
    roles = ("baseline_1", "baseline_2", "quote", "escaped_quote", "literal_control",
             "true_17", "false_17", "true_23", "false_23", "recovery")
    report = ScanReport(target="http://127.0.0.1/rest/products/search?q=apple", started_at=utc_now(), settings={"samples": 2})
    for index, role in enumerate(roles, 1):
        nonempty = role.startswith(("baseline", "true")) or role == "recovery"
        quote = role == "quote"
        report.probes.append(ProbeEvidence(
            request_id=index, role=role, parameter="q", input_value="unit fixture",
            response_received=True, product_count=None if quote else 2 if nonempty else 0,
            product_ids_sha256=None if quote else "catalog" if nonempty else "empty",
            sql_error_signatures=["SQLITE_ERROR"] if quote else [],
        ))
        report.responses.append(ResponseEvidence(
            index, report.target, utc_now(), 500 if quote else 200,
            "application/json", 0, "unit-hash", 0, b"",
        ))
    return report


def change_probe(report, role, **changes):
    index = next(i for i, probe in enumerate(report.probes) if probe.role == role)
    report.probes[index] = replace(report.probes[index], **changes)


def test_complete_independent_controls_are_required_to_confirm(decision_report):
    result = assess(decision_report, 2)
    assert result.outcome == "confirmed"
    assert all(result.checks.values())


@pytest.mark.parametrize("role,changes", [
    ("baseline_2", {"product_ids_sha256": "changed"}),
    ("recovery", {"response_received": False}),
    ("true_17", {"product_ids_sha256": "same-count-different-products"}),
    ("false_23", {"product_count": 1, "product_ids_sha256": "unexpected"}),
    ("escaped_quote", {"product_count": None}),
    ("quote", {"sql_error_signatures": []}),
])
def test_a_missing_control_downgrades_confirmation(decision_report, role, changes):
    change_probe(decision_report, role, **changes)
    result = assess(decision_report, 2)
    assert result.outcome == "suspected"
    assert result.limitations


def test_sql_error_without_boolean_evidence_is_only_suspicion(decision_report):
    for role in ("true_17", "true_23"):
        change_probe(decision_report, role, product_count=0, product_ids_sha256="empty")
    assert assess(decision_report, 2).outcome == "suspected"


def test_generic_http_error_does_not_generate_sql_suspicion(decision_report):
    for role in ("true_17", "true_23"):
        change_probe(decision_report, role, product_count=0, product_ids_sha256="empty")
    change_probe(decision_report, "quote", sql_error_signatures=[])
    assert assess(decision_report, 2).outcome == "not_detected"


def test_missing_collection_is_inconclusive_not_negative(decision_report):
    decision_report.responses.clear()
    decision_report.probes.clear()
    assert assess(decision_report, 2).outcome == "inconclusive"


@pytest.mark.parametrize("payload", [
    None, [], {"data": []}, {"status": "success", "data": "wrong"},
    {"status": "success", "data": [{"id": True, "name": "x"}]},
    {"status": "success", "data": [{"id": "1", "name": "x"}]},
    {"status": "success", "data": [{"id": 1, "name": "x"}, {"id": 1, "name": "x"}]},
])
def test_valid_json_with_invalid_product_schema_is_not_evidence(decision_report, payload):
    reply = replace(decision_report.responses[0], body=json.dumps(payload).encode())
    observation = observe(decision_report.probes[0], reply)
    assert observation.response_received
    assert observation.product_count is None and observation.product_ids_sha256 is None


def test_order_and_descriptions_do_not_change_product_identity(decision_report):
    first = replace(decision_report.responses[0], body=b'{"status":"success","data":[{"id":9,"name":"a"},{"id":4,"name":"b"}]}')
    second = replace(first, body=b'{"status":"success","data":[{"id":4,"name":"new"},{"id":9,"name":"translated"}]}')
    before = observe(decision_report.probes[0], first)
    after = observe(decision_report.probes[0], second)
    assert before.product_count == after.product_count == 2
    assert before.product_ids_sha256 == after.product_ids_sha256


@pytest.mark.parametrize("status,media,body", [
    (200, "text/html", b'<html>SQLITE_ERROR</html>'),
    (500, "application/json", b'{"status":"success","data":[]}'),
    (200, "application/json", b'{invalid-json'),
])
def test_fallback_errors_and_invalid_json_are_not_product_results(decision_report, status, media, body):
    reply = replace(decision_report.responses[0], status_code=status, content_type=media, body=body)
    observation = observe(decision_report.probes[0], reply)
    assert observation.product_count is None
