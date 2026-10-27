import json
import threading
from unittest.mock import Mock
from urllib.parse import urlencode

import pytest

from experiments.run_control import run_experiment
from experiments.sqlite_control import ControlServer, SAFE_PATH, VULNERABLE_PATH
from scanner.core import run_sqli
from scanner.http_client import HttpClient
from scanner.modules.sqli import build_probe_plan


@pytest.fixture
def control_server():
    server = ControlServer(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.mark.parametrize("term", ["apple", "orange", "water", "nonexistent", "", "%", "_"])
def test_endpoints_share_normal_search_results(control_server, term):
    _, base = control_server
    with HttpClient(interval=0) as client:
        vulnerable = client.get(base + VULNERABLE_PATH + "?" + urlencode({"q": term}))
        safe = client.get(base + SAFE_PATH + "?" + urlencode({"q": term}))
    assert vulnerable.status_code == safe.status_code == 200
    assert vulnerable.body == safe.body
    rows = json.loads(safe.body)["data"]
    assert 5 not in [row["id"] for row in rows]  # Registro excluído é filtrado em ambos.
    if term == "apple":
        assert sorted(row["id"] for row in rows) == [1, 2, 3]  # Inclui busca na descrição.


def test_sql_error_is_real_and_parameterized_query_treats_quote_as_data(control_server):
    _, base = control_server
    query = "?" + urlencode({"q": "apple'"})
    with HttpClient(interval=0) as client:
        vulnerable = client.get(base + VULNERABLE_PATH + query)
        safe = client.get(base + SAFE_PATH + query)
    assert vulnerable.status_code == 500
    assert json.loads(vulnerable.body)["error"]["name"] == "SQLITE_ERROR"
    assert safe.status_code == 200
    assert json.loads(safe.body) == {"status": "success", "data": []}


def test_actual_app_scans_positive_and_negative_controls_without_changing_data(control_server):
    server, base = control_server
    before = server.database.manifest()
    vulnerable = run_sqli(base + VULNERABLE_PATH + "?q=apple", interval=0)
    safe = run_sqli(base + SAFE_PATH + "?q=apple", interval=0)
    assert vulnerable.assessment.outcome == "confirmed"
    assert all(vulnerable.assessment.checks.values())
    assert len(vulnerable.findings) == 1
    assert safe.assessment.outcome == "not_detected"
    assert safe.findings == []
    assert len(vulnerable.responses) == len(safe.responses) == 10
    assert [probe.product_count for probe in vulnerable.probes] == [3, 3, None, 0, 0, 3, 0, 3, 0, 3]
    assert [probe.product_count for probe in safe.probes] == [3, 3, 0, 0, 0, 0, 0, 0, 0, 3]
    assert vulnerable.probes[0].product_ids_sha256 == safe.probes[0].product_ids_sha256
    assert server.database.manifest() == before
    assert [(p.role, p.input_value) for p in vulnerable.probes] == [(p.role, p.input_value) for p in safe.probes]


def test_runner_records_each_repeat_and_metrics(control_server, tmp_path):
    _, base = control_server
    summary = run_experiment(base, tmp_path, repetitions=2, interval=0)
    assert summary["status"] == "completed"
    assert summary["metrics"] == {
        "true_positive": 2, "true_negative": 2, "false_positive": 0,
        "false_negative": 0, "inconclusive": 0,
    }
    assert summary["dataset_unchanged"] and summary["same_baseline_products"]
    assert len(summary["runs"]) == 4
    assert (tmp_path / "summary.json").exists()
    assert summary == json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    for run in summary["runs"]:
        report = json.loads((tmp_path / run["report"]).read_text(encoding="utf-8"))
        assert report["assessment"]["outcome"] == run["outcome"]
        assert len(report["responses"]) == 10
        assert all("body" not in response for response in report["responses"])


def test_classification_follows_sql_behavior_not_endpoint_name(control_server, tmp_path):
    server, base = control_server
    # Inverte as implementações reais. A análise do scanner permanece intocada.
    server.routes = {VULNERABLE_PATH: True, SAFE_PATH: False}
    summary = run_experiment(base, tmp_path, repetitions=1, interval=0)
    assert [run["outcome"] for run in summary["runs"]] == ["not_detected", "confirmed"]
    assert summary["metrics"] == {
        "true_positive": 0, "true_negative": 0, "false_positive": 1,
        "false_negative": 1, "inconclusive": 0,
    }
    assert summary["status"] == "completed"  # Resultado contrário à hipótese não é ocultado.


def test_unavailable_control_is_not_counted_as_true_negative(local_server, tmp_path):
    base, _ = local_server  # /health não identifica o laboratório.
    summary = run_experiment(base, tmp_path, repetitions=1, interval=0)
    assert summary["status"] == "incomplete"
    assert summary["runs"] == []
    assert summary["metrics"]["true_negative"] == 0
    assert "error" in summary["dataset_before"]
    assert (tmp_path / "summary.json").exists()


def test_inconclusive_scans_are_abstentions(control_server, tmp_path, monkeypatch):
    _, base = control_server
    # Termo sem resultados: dados e scanner reais, só altera o termo do experimento.
    from experiments import run_control
    original = run_control.run_sqli

    def empty_baseline(url, **kwargs):
        return original(url.replace("q=apple", "q=nonexistent"), **kwargs)

    monkeypatch.setattr(run_control, "run_sqli", empty_baseline)
    summary = run_experiment(base, tmp_path, repetitions=1, interval=0)
    assert summary["status"] == "incomplete"
    assert summary["runs"][1]["outcome"] == "inconclusive"
    assert summary["metrics"]["true_negative"] == 0
    assert summary["metrics"]["inconclusive"] == 1


@pytest.mark.parametrize("path", [VULNERABLE_PATH, SAFE_PATH, "/rest/products/search"])
def test_identical_probe_plan_for_all_supported_paths(path):
    expected = build_probe_plan("http://localhost:3000/rest/products/search?q=apple", 2, 10)
    assert build_probe_plan("http://localhost:8001" + path + "?q=apple", 2, 10) == expected


@pytest.mark.parametrize("url", ["http://example.com", "http://127.0.0.1:8001/other", "http://localhost:8001/?q=x"])
def test_runner_rejects_invalid_origin_before_network(url, tmp_path, monkeypatch):
    send = Mock()
    monkeypatch.setattr("requests.Session.get", send)
    with pytest.raises(ValueError):
        run_experiment(url, tmp_path)
    send.assert_not_called()
