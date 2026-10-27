from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sqlite3
import threading
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest

from main import main
from scanner.core import run_sqli
from scanner.models import Confidence, FindingStatus
from scanner.modules.sqli import assess, build_probe_plan, observe, probe_url
from scanner.reporter import write_json


@pytest.fixture
def product_server():
    """Mesma forma de consulta do laboratório, com alternativa parametrizada."""
    servers = []

    def start(mode="vulnerable"):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                term = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
                requests.append(term)
                status = 200
                content_type = "application/json"
                try:
                    with sqlite3.connect(":memory:") as database:
                        database.row_factory = sqlite3.Row
                        database.executescript("""
                            CREATE TABLE Products (id INTEGER, name TEXT, description TEXT, deletedAt TEXT);
                            INSERT INTO Products VALUES (1, 'Apple juice', 'Fresh', NULL);
                            INSERT INTO Products VALUES (2, 'Water', 'Apple flavour', NULL);
                            INSERT INTO Products VALUES (3, 'Orange', 'Fresh', NULL);
                            INSERT INTO Products VALUES (4, 'Apple deleted', 'Fresh', '2020-01-01');
                        """)
                        if mode in {"parameterized", "error_only", "generic_error"}:
                            if term == "apple'" and mode != "parameterized":
                                raise sqlite3.OperationalError("fixture error")
                            rows = database.execute(
                                "SELECT * FROM Products WHERE ((name LIKE ? OR description LIKE ?) "
                                "AND deletedAt IS NULL) ORDER BY name", (f"%{term}%", f"%{term}%")
                            ).fetchall()
                        else:
                            rows = database.execute(
                                "SELECT * FROM Products WHERE ((name LIKE '%" + term + "%' "
                                "OR description LIKE '%" + term + "%') AND deletedAt IS NULL) ORDER BY name"
                            ).fetchall()
                        data = [dict(row) for row in rows]
                        if mode == "unstable" and len(requests) == 2:
                            data = data[:1]
                        if mode == "wrong_true_ids" and "AND (" in term and len(data) > 0:
                            data[0]["id"] = 99
                        payload = json.dumps({"status": "success", "data": data}).encode()
                except sqlite3.OperationalError:
                    status = 500
                    payload = b"SQLITE_ERROR: syntax error"
                    if mode == "generic_error":
                        payload = b"Internal Server Error"
                if mode == "html":
                    content_type = "text/html"
                    payload = b"<html>generic fallback</html>"
                if mode == "malformed":
                    payload = b'{"data":'
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        return f"http://127.0.0.1:{server.server_port}/rest/products/search?q=apple", requests

    yield start
    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join()


def test_confirms_boolean_sqli_with_complete_controls(product_server, tmp_path):
    url, requests = product_server()
    report = run_sqli(url, interval=0)
    assert len(requests) == 10
    assert len(report.responses) == 10
    assert all(report.assessment.checks.values())
    assert report.assessment.outcome == "confirmed"
    assert report.findings[0].status == FindingStatus.CONFIRMED
    assert report.findings[0].confidence == Confidence.HIGH
    assert [probe.product_count for probe in report.probes] == [2, 2, None, 0, 0, 2, 0, 2, 0, 2]
    assert report.probes[2].sql_error_signatures == ["SQLITE_ERROR"]
    assert len(report.comparisons) == 9
    output = write_json(report, tmp_path / "sqli.json")
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["assessment"]["outcome"] == "confirmed"
    assert data["probes"][5]["product_ids_sha256"] == data["probes"][0]["product_ids_sha256"]
    assert data["probes"][6]["input_value"].count("17=18") == 1
    assert data["findings"][0]["evidence_request_ids"] == list(range(1, 11))
    assert "Apple juice" not in output.read_text(encoding="utf-8")
    assert "deletedAt" not in output.read_text(encoding="utf-8")


@pytest.mark.parametrize(("mode", "outcome", "findings"), [
    ("parameterized", "not_detected", 0),
    ("error_only", "suspected", 1),
    ("generic_error", "not_detected", 0),
    ("unstable", "suspected", 1),
    ("wrong_true_ids", "suspected", 1),
    ("html", "inconclusive", 0),
    ("malformed", "inconclusive", 0),
])
def test_avoids_confirmation_without_required_evidence(product_server, mode, outcome, findings):
    url, _ = product_server(mode)
    report = run_sqli(url, interval=0)
    assert report.assessment.outcome == outcome
    assert len(report.findings) == findings
    assert not any(finding.status == FindingStatus.CONFIRMED for finding in report.findings)


def test_empty_baseline_only_supports_error_suspicion(product_server):
    url, _ = product_server()
    report = run_sqli(url.replace("q=apple", "q=nonexistent"), interval=0)
    assert report.probes[0].product_count == 0
    assert report.assessment.outcome == "suspected"
    assert not report.assessment.checks["baseline_nonempty"]


def test_transport_failure_is_inconclusive_and_serializable(local_server, tmp_path, capsys):
    url, _ = local_server
    output = tmp_path / "failure.json"
    result = main([url + "/rest/products/search?q=apple", "--module", "sqli",
                   "--max-body-bytes", "1", "--output", str(output)])
    assert result == 1
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["assessment"]["outcome"] == "inconclusive"
    assert data["errors"][0]["request_id"] == data["probes"][0]["request_id"]
    assert not data["probes"][0]["response_received"]
    assert "SQLi: inconclusive" in capsys.readouterr().out


def test_missing_or_failed_recovery_never_confirms(product_server):
    url, _ = product_server()
    report = run_sqli(url, interval=0)
    report.probes.pop()
    report.responses.pop()
    result = assess(report, 2)
    assert result.outcome == "suspected"
    assert not result.checks["all_requests_completed"]
    assert not result.checks["recovery_matches"]


def test_does_not_use_body_similarity_for_confirmation(product_server):
    url, _ = product_server()
    report = run_sqli(url, interval=0)
    original = report.responses[0]
    changed = replace(original, body=b'{"status":"success","data":['
                      b'{"id":2,"name":"Renamed"},{"id":1,"name":"Translated"}]}')
    observation = observe(report.probes[0], changed)
    assert observation.product_ids_sha256 == report.probes[0].product_ids_sha256
    assert observation.product_count == 2


def test_valid_json_with_wrong_shape_is_not_product_evidence(product_server):
    url, _ = product_server()
    report = run_sqli(url, interval=0)
    for body in (b"[]", b"null", b'{"status":"success","data":[{"id":true,"name":"x"}]}',
                 b'{"status":"success","data":[{"id":1,"name":"x"},{"id":1,"name":"x"}]}'):
        result = observe(report.probes[0], replace(report.responses[0], body=body))
        assert result.product_count is None
        assert result.product_ids_sha256 is None


def test_plan_preserves_other_parameters_and_encodes_injection():
    url = "http://localhost:3000/rest/products/search?lang=pt&q=apple&flag=&lang=en"
    plan = build_probe_plan(url, 3, 11)
    assert len(plan) == 11
    query = parse_qs(urlsplit(probe_url(url, plan[6].input_value)).query, keep_blank_values=True)
    assert query["lang"] == ["pt", "en"]
    assert query["flag"] == [""]
    assert query["q"] == [plan[6].input_value]


@pytest.mark.parametrize("arguments", [
    ["http://example.com/rest/products/search?q=apple"],
    ["http://localhost:3000/"],
    ["http://localhost:3000/rest/products/search"],
    ["http://localhost:3000/rest/products/search?q=apple&q=water"],
    ["http://localhost:3000/rest/products/search?q="],
    ["http://localhost:3000/rest/products/search?q=apple%27"],
    ["http://localhost:3000/rest/products/search?q=apple", "--samples", "1"],
    ["http://localhost:3000/rest/products/search?q=apple", "--samples", "3"],
    ["http://localhost:3000/rest/products/search?q=apple", "--max-requests", "9"],
])
def test_invalid_sqli_invocation_never_sends_requests(arguments, monkeypatch):
    send = Mock()
    monkeypatch.setattr("requests.Session.get", send)
    with pytest.raises(SystemExit) as raised:
        main(arguments + ["--module", "sqli"])
    assert raised.value.code == 2
    send.assert_not_called()


def test_sqli_cli_reports_finding_without_treating_quote_500_as_network_failure(product_server, tmp_path, capsys):
    url, _ = product_server()
    output = tmp_path / "cli.json"
    assert main([url, "--module", "sqli", "--interval", "0", "--output", str(output)]) == 0
    assert "SQLi: confirmed" in capsys.readouterr().out
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["summary"]["errors"] == 0
    assert data["responses"][2]["status_code"] == 500
