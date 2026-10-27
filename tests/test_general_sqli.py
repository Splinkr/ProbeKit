"""Generalização validada contra as consultas reais do laboratório SQLite."""

from dataclasses import replace
import json
from urllib.parse import parse_qsl, urlsplit
from unittest.mock import Mock

import pytest

from main import main
from scanner.core import run_sqli
from scanner.models import ResponseEvidence, utc_now
from scanner.sqli_features import extract_features
from scanner.sqli_plans import available_parameters, build_probe_plan, probe_url


@pytest.mark.parametrize("format,parameter,context,term", [
    ("json", "term", "like", "apple"),
    ("html", "search", "like", "apple"),
    ("text", "keyword", "like", "apple"),
    ("quoted", "item", "quoted", "Apple+Demo"),
])
@pytest.mark.parametrize("implementation,expected", [("vulnerable", "confirmed"), ("safe", "not_detected")])
def test_real_queries_across_names_formats_and_contexts(sqlite_app, format, parameter, context, term, implementation, expected):
    before = sqlite_app.server.database.manifest()
    url = sqlite_app.url + f"/general/{format}/{implementation}?{parameter}={term}&lang=en"
    report = run_sqli(url, parameter=parameter, context=context, interval=0)
    assert report.assessment.outcome == expected
    assert len(report.responses) == 10 and report.errors == []
    assert report.parameter_results[0].parameter == parameter
    assert report.settings["available_parameters"] == [parameter, "lang"]
    assert report.parameter_results[0].assessment.outcome == expected
    assert all(probe.parameter == parameter for probe in report.probes)
    assert len(report.findings) == (1 if expected == "confirmed" else 0)
    if report.findings:
        assert report.findings[0].parameter == parameter
        assert all(report.assessment.checks.values())
    assert sqlite_app.server.database.manifest() == before


def test_multi_parameter_run_is_independent_and_uses_one_global_budget(sqlite_app):
    report = run_sqli(sqlite_app.url + "/general/html/vulnerable?search=apple&lang=en",
                      all_parameters=True, max_requests=20, interval=0)
    assert [(result.parameter, result.assessment.outcome) for result in report.parameter_results] == [
        ("search", "confirmed"), ("lang", "not_detected")]
    assert len(report.responses) == 20
    assert [response.request_id for response in report.responses] == list(range(1, 21))
    assert [finding.parameter for finding in report.findings] == ["search"]
    assert report.findings[0].evidence_request_ids == list(range(1, 11))
    assert report.parameter_results[1].evidence_request_ids == list(range(11, 21))
    for response, probe in zip(report.responses, report.probes):
        values = dict(parse_qsl(urlsplit(response.url).query))
        assert values["lang" if probe.parameter == "search" else "search"] == ("en" if probe.parameter == "search" else "apple")


def test_unselected_query_tokens_remain_byte_for_byte_unchanged():
    url = "http://localhost:8001/arbitrary?lang=pt%20BR&tag=one&tag=two&blank&term=apple&signature=%2f"
    mutated = probe_url(url, "probe value'", "term")
    assert urlsplit(mutated).query == "lang=pt%20BR&tag=one&tag=two&blank&term=probe+value%27&signature=%2f"
    assert available_parameters(url) == ["lang", "tag", "blank", "term", "signature"]


def test_repeated_unselected_fields_survive_real_http(sqlite_app):
    url = sqlite_app.url + "/general/json/vulnerable?term=apple&tag=one&tag=two&blank=&lang=en"
    report = run_sqli(url, parameter="term", interval=0)
    assert report.assessment.outcome == "confirmed"
    for response in report.responses:
        assert [(key, value) for key, value in parse_qsl(urlsplit(response.url).query, keep_blank_values=True) if key != "term"] == [
            ("tag", "one"), ("tag", "two"), ("blank", ""), ("lang", "en")]


@pytest.mark.parametrize("path", ["unstable", "error"])
def test_instability_and_status_200_error_pages_never_confirm(sqlite_app, path):
    report = run_sqli(sqlite_app.url + f"/general/html/{path}?search=apple", interval=0)
    assert report.assessment.outcome == "inconclusive"
    assert report.findings == []
    assert report.assessment.limitations


def test_wrong_sql_context_keeps_error_as_suspicion(sqlite_app):
    report = run_sqli(sqlite_app.url + "/general/json/vulnerable?term=apple", context="quoted", interval=0)
    assert report.assessment.outcome == "suspected"
    assert report.assessment.checks["new_sql_error"]
    assert not report.assessment.checks["boolean_pair_17"]


@pytest.mark.parametrize("url,options", [
    ("http://localhost:8001/custom?term=apple&lang=en", {}),
    ("http://localhost:8001/custom?term=apple&lang=en", {"all_parameters": True, "max_requests": 10}),
    ("http://localhost:8001/custom?term=apple", {"parameter": "missing"}),
    ("http://localhost:8001/custom?term=apple&term=water", {"parameter": "term"}),
    ("http://localhost:8001/custom?term=apple", {"parameter": "term", "all_parameters": True}),
    ("http://example.invalid/custom?term=apple", {"parameter": "term"}),
])
def test_selection_and_budget_are_validated_before_any_network(url, options, monkeypatch):
    send = Mock()
    monkeypatch.setattr("requests.Session.get", send)
    with pytest.raises(ValueError):
        run_sqli(url, **options)
    send.assert_not_called()


def test_unknown_paths_are_supported_without_a_route_allowlist():
    plan = build_probe_plan("http://localhost:8001/anything?needle=apple", 2, 10)
    assert all(probe.parameter == "needle" for probe in plan)
    assert len(plan) == 10


def test_generic_cli_serializes_each_parameter_and_specific_findings(sqlite_app, tmp_path):
    output = tmp_path / "generic.json"
    assert main([sqlite_app.url + "/general/json/vulnerable?term=apple&lang=en", "--module", "sqli",
                 "--all-parameters", "--max-requests", "20", "--interval", "0", "--output", str(output)]) == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert [(result["parameter"], result["assessment"]["outcome"]) for result in data["parameter_results"]] == [
        ("term", "confirmed"), ("lang", "not_detected")]
    assert data["findings"][0]["parameter"] == "term"
    assert "label" not in data["probes"][0]["features"]
    assert all("body" not in response for response in data["responses"])


def evidence(body, media="application/json", status=200):
    return ResponseEvidence(1, "http://127.0.0.1/custom", utc_now(), status, media, len(body), "unit", 0, body)


def test_json_identity_ignores_order_and_metadata_without_erasing_result_changes():
    first = extract_features(evidence(b'{"items":[{"sku":"b","label":"B"},{"sku":"a","label":"A"}],"nonce":1}'))
    second = extract_features(evidence(b'{"items":[{"sku":"a","label":"renamed"},{"sku":"b","label":"B"}],"nonce":2}'))
    changed = extract_features(evidence(b'{"items":[{"sku":"c","label":"C"}],"nonce":3}'))
    assert first.valid and second.valid and first.result_count == 2
    assert first.fingerprint == second.fingerprint != changed.fingerprint


def test_html_whitespace_and_script_variation_are_not_visible_result_changes():
    first = extract_features(evidence(b'<title>Catalog</title><p>Apple demo</p><script>nonce=1</script>', "text/html"))
    second = extract_features(evidence(b'<title>Catalog</title>\n<p>Apple   demo</p><script>nonce=2</script>', "text/html"))
    assert first.valid and second.valid and first.fingerprint == second.fingerprint


@pytest.mark.parametrize("body,media", [
    (b'{"status":"error","data":[]}', "application/json"),
    (b'<title>Error</title><p>Service unavailable</p>', "text/html"),
    (b'Internal Server Error', "text/plain"),
    (b'{invalid', "application/json"),
    (b'opaque', "application/octet-stream"),
])
def test_error_pages_and_unsupported_formats_are_not_valid_controls(body, media):
    assert not extract_features(evidence(body, media)).valid


def test_general_experiment_records_inconclusive_cases_honestly(sqlite_app, tmp_path):
    from experiments.run_general_sqli import run_experiment

    summary = run_experiment(sqlite_app.url, tmp_path, case_names=["json-vulnerable", "html-safe", "error-page"], interval=0)
    assert summary["status"] == "completed" and summary["expectations_matched"]
    assert [run["outcomes"] for run in summary["runs"]] == [
        {"term": "confirmed"}, {"search": "not_detected"}, {"search": "inconclusive"}]
    assert summary["dataset_unchanged"]
    for run in summary["runs"]:
        data = json.loads((tmp_path / run["report"]).read_text(encoding="utf-8"))
        assert data["parameter_results"][0]["assessment"]["outcome"] == next(iter(run["outcomes"].values()))


def test_experiment_expectations_do_not_override_observed_classification(sqlite_app, tmp_path):
    from experiments.run_general_sqli import run_experiment

    route = sqlite_app.server.general_routes["/general/json/vulnerable"]
    sqlite_app.server.general_routes["/general/json/vulnerable"] = replace(route, parameterized=True)
    summary = run_experiment(sqlite_app.url, tmp_path, case_names=["json-vulnerable"], interval=0)
    assert not summary["expectations_matched"]
    assert summary["runs"][0]["outcomes"] == {"term": "not_detected"}
    assert summary["runs"][0]["expected_outcomes"] == {"term": "confirmed"}


def test_json_status_can_be_structured_without_crashing_feature_extraction():
    assert extract_features(evidence(b'{"status":{"code":200},"items":[]}')).valid
