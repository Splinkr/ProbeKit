"""Controle empírico contra a aplicação real, sem depender de portas fixas."""

import json
from urllib.parse import urlencode

import pytest

from experiments.run_control import run_experiment
from experiments.sqlite_control import ControlServer, SAFE_PATH, VULNERABLE_PATH
from scanner.core import run_sqli
from scanner.http_client import HttpClient


@pytest.mark.parametrize("term", ["apple", "orange", "nonexistent", "", "%", "_"])
def test_normal_queries_are_equivalent_over_the_shared_database(sqlite_app, term):
    with HttpClient(interval=0) as client:
        replies = [client.get(sqlite_app.url + path + "?" + urlencode({"q": term}))
                   for path in (VULNERABLE_PATH, SAFE_PATH)]
    assert replies[0].body == replies[1].body
    data = json.loads(replies[0].body)["data"]
    assert all(row["id"] != 5 for row in data)
    if term == "apple":
        assert {row["id"] for row in data} == {1, 2, 3}


@pytest.mark.parametrize("samples,budget", [(2, 10), (3, 11)])
def test_same_detector_distinguishes_real_sql_implementations(sqlite_app, samples, budget):
    before = sqlite_app.server.database.manifest()
    reports = [run_sqli(sqlite_app.url + path + "?q=apple", samples=samples,
                        max_requests=budget, interval=0) for path in (VULNERABLE_PATH, SAFE_PATH)]
    positive, negative = reports
    assert positive.assessment.outcome == "confirmed" and len(positive.findings) == 1
    assert all(positive.assessment.checks.values())
    assert negative.assessment.outcome == "not_detected" and negative.findings == []
    assert all(len(report.responses) == budget and not report.errors for report in reports)
    assert [(p.role, p.input_value) for p in positive.probes] == [(p.role, p.input_value) for p in negative.probes]
    assert positive.probes[0].product_ids_sha256 == negative.probes[0].product_ids_sha256
    assert sqlite_app.server.database.manifest() == before


def test_sql_implementation_overrides_names_and_expectations(sqlite_app, tmp_path):
    sqlite_app.server.routes = {VULNERABLE_PATH: True, SAFE_PATH: False}
    result = run_experiment(sqlite_app.url, tmp_path, repetitions=1, interval=0)
    assert [run["outcome"] for run in result["runs"]] == ["not_detected", "confirmed"]
    assert result["metrics"]["false_positive"] == result["metrics"]["false_negative"] == 1
    assert result["metrics"]["true_positive"] == result["metrics"]["true_negative"] == 0


def test_each_repetition_has_its_own_verifiable_report(sqlite_app, tmp_path):
    result = run_experiment(sqlite_app.url, tmp_path, repetitions=2, interval=0)
    assert result["status"] == "completed"
    assert result["dataset_unchanged"] and result["same_baseline_products"]
    assert result["metrics"] == {"true_positive": 2, "true_negative": 2,
                                  "false_positive": 0, "false_negative": 0, "inconclusive": 0}
    assert len(list(tmp_path.glob("*.json"))) == 5
    assert json.loads((tmp_path / "summary.json").read_text(encoding="utf-8")) == result
    for run in result["runs"]:
        report = json.loads((tmp_path / run["report"]).read_text(encoding="utf-8"))
        assert report["target"] == run["target"]
        assert report["assessment"]["outcome"] == run["outcome"]
        assert report["summary"]["requests_attempted"] == 10


def test_empty_reference_cannot_be_counted_as_a_safe_negative(sqlite_app, tmp_path, monkeypatch):
    import experiments.run_control as experiment

    detector = experiment.run_sqli
    monkeypatch.setattr(experiment, "run_sqli", lambda url, **kw: detector(url.replace("apple", "no-such-product"), **kw))
    result = run_experiment(sqlite_app.url, tmp_path, repetitions=1, interval=0)
    assert result["status"] == "incomplete"
    assert result["metrics"]["inconclusive"] == 1
    assert result["metrics"]["true_negative"] == 0


def test_unrecognized_service_is_not_scanned_as_the_control(http_lab, tmp_path):
    origin = http_lab.start(lambda _: http_lab.reply(body=b'{}', headers={"Content-Type": "application/json"}))
    result = run_experiment(origin.url, tmp_path, repetitions=1, interval=0)
    assert result["runs"] == [] and result["status"] == "incomplete"
    assert result["metrics"]["true_negative"] == 0
    assert all(call.path == "/health" for call in origin.calls)


def test_active_control_port_cannot_be_claimed_by_another_instance(sqlite_app):
    with pytest.raises(OSError):
        ControlServer(sqlite_app.server.server_port)


@pytest.mark.parametrize("query", ["", "?q=a&q=b", "?q=" + "a" * 201])
def test_control_rejects_ambiguous_or_oversized_parameters(sqlite_app, query):
    with HttpClient() as client:
        response = client.get(sqlite_app.url + SAFE_PATH + query)
    assert response.status_code == 400
