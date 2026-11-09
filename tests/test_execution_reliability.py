"""R01: falha de processamento não é argumento inválido nem sucesso de coleta."""

from copy import deepcopy
import json
from unittest.mock import Mock

import pytest

from main import main
from scanner.core import run_baseline, run_sqli
from scanner.discovery import discover
from scanner.modules.exposure import run_exposure
from scanner.modules.xss import run_xss
from scanner.pipeline import run_scan


SECRET = "PRIVATE_PROCESSING_SENTINEL"


def crash(*_args, **_kwargs):
    raise ValueError(SECRET)


def snapshots():
    saved = []
    return saved, lambda report: saved.append(deepcopy(report.to_dict()))


def test_charset_idna_is_recovered_by_the_real_cli(http_lab, tmp_path):
    site = http_lab.start(lambda _: http_lab.reply(body=b"<p>ready</p>", headers={"Content-Type": "text/html; charset=idna"}))
    output = tmp_path / "scan.json"
    assert main(["scan", site.url, "--interval", "0", "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["status"] == "completed"


@pytest.mark.parametrize("mode", ["discover", "scan"])
def test_unexpected_discovery_error_preserves_pages_and_returns_one(http_lab, monkeypatch, tmp_path, mode):
    site = http_lab.start(lambda _: http_lab.reply(body=b'<a href="/next?q=apple">next</a>', headers={"Content-Type": "text/html"}))
    monkeypatch.setattr("scanner.discovery.HtmlInventoryParser.feed", crash)
    output = tmp_path / "failed.json"
    assert main([mode, site.url, "--interval", "0", "--output", str(output)]) == 1
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["summary"]["status"] == data["collection_status"] == "incomplete"
    assert data["execution_errors"][0]["kind"] == "execution_error"
    inventory = data["discovery"] if mode == "scan" else data
    assert len(inventory["pages"]) == len(site.calls) == 1
    assert inventory["summary"]["requests_attempted"] == 1
    assert inventory["errors"] == []
    assert SECRET not in json.dumps(data)


@pytest.mark.parametrize("module,hook", [
    ("sqli", "scanner.modules.sqli.observe"),
    ("xss", "scanner.modules.xss.inspect_response"),
    ("exposure", "scanner.modules.exposure.observe"),
])
def test_analysis_failure_stops_scan_and_keeps_a_final_checkpoint(sqlite_app, monkeypatch, module, hook):
    monkeypatch.setattr(hook, crash)
    saved, checkpoint = snapshots()
    report = run_scan(sqlite_app.url + "/probekit-lab", modules=(module,), interval=0, checkpoint=checkpoint)
    data = saved[-1]
    assert report.status == data["summary"]["status"] == data["collection_status"] == "incomplete"
    assert data["finished_at"]
    assert data["execution_errors"][0]["module"] == module
    assert len(report.requests) == report.discovery.requests_attempted + 1
    assert report.targets[0]["status"] == "failed"
    assert all(target["status"] == "skipped" for target in report.targets[1:])
    assert all(item["reason"] == "execution_error" for item in report.ignored_targets if item.get("status") in {"failed", "skipped"})
    assert report.analyses[0].to_dict()["summary"]["requests_attempted"] == 1
    assert SECRET not in json.dumps(data)


def test_failure_before_any_classification_does_not_mask_the_original_error(sqlite_app, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.run_detection", crash)
    saved, checkpoint = snapshots()
    report = run_scan(sqlite_app.url + "/control/vulnerable/search?q=apple", interval=0, checkpoint=checkpoint)
    assert report.analyses[0].assessment is None
    assert report.status == saved[-1]["summary"]["status"] == "incomplete"
    assert saved[-1]["analysis_summary"]["evaluations"] == 0
    assert len(report.requests) == 1


def test_completed_findings_survive_a_later_analysis_failure(sqlite_app, monkeypatch):
    import scanner.pipeline as pipeline

    original = pipeline.run_detection
    calls = 0

    def detect(*args):
        nonlocal calls
        calls += 1
        if calls == 4:
            crash()
        return original(*args)

    monkeypatch.setattr(pipeline, "run_detection", detect)
    report = run_scan(sqlite_app.url + "/probekit-lab", interval=0)
    assert report.status == "incomplete"
    assert len(report.analyses) == 4
    assert report.analyses[2].assessment.outcome == "confirmed"
    assert report.analyses[2].findings[0].status == "confirmed"
    assert all(target["status"] == "completed" for target in report.targets[:3])
    assert report.targets[3]["status"] == "failed"


@pytest.mark.parametrize("runner,path,hook", [
    (run_baseline, "/health", "scanner.core.compare_responses"),
    (run_sqli, "/control/vulnerable/search?q=apple", "scanner.modules.sqli.observe"),
    (run_xss, "/xss/html/raw?q=demo", "scanner.modules.xss.inspect_response"),
    (run_exposure, "/", "scanner.modules.exposure.observe"),
])
def test_direct_runners_capture_processing_errors_without_double_counting(sqlite_app, monkeypatch, runner, path, hook):
    monkeypatch.setattr(hook, crash)
    report = runner(sqlite_app.url + path, interval=0)
    data = report.to_dict()
    expected = 2 if runner is run_baseline else 1
    assert data["summary"]["requests_attempted"] == expected
    assert data["summary"]["status"] == data["collection_status"] == "incomplete"
    assert len(data["execution_errors"]) == 1
    assert data["errors"] == []
    assert SECRET not in json.dumps(data)
    if runner in {run_baseline, run_sqli, run_xss}:
        assert len(report.responses) == expected


@pytest.mark.parametrize("module,hook", [
    ("baseline", "scanner.core.compare_responses"),
    ("sqli", "scanner.modules.sqli.observe"),
    ("xss", "scanner.modules.xss.inspect_response"),
    ("exposure", "scanner.modules.exposure.observe"),
])
def test_direct_cli_processing_failure_exits_one(sqlite_app, monkeypatch, tmp_path, capsys, module, hook):
    monkeypatch.setattr(hook, crash)
    path = "/" if module == "exposure" else "/control/vulnerable/search?q=apple"
    assert main([sqlite_app.url + path, "--module", module, "--interval", "0", "--output", str(tmp_path / "report.json")]) == 1
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err


def test_checkpoint_oserror_is_preserved_when_final_save_also_fails(sqlite_app):
    primary = OSError("first checkpoint failure")
    calls = 0
    saved = []

    def checkpoint(report):
        nonlocal calls
        calls += 1
        saved.append(deepcopy(report.to_dict()))
        if calls == 2:
            raise primary
        if calls > 2:
            raise OSError("secondary checkpoint failure")

    with pytest.raises(OSError) as error:
        run_scan(sqlite_app.url + "/probekit-lab", interval=0, checkpoint=checkpoint)
    assert error.value is primary
    assert saved[-1]["summary"]["status"] == "incomplete"


def test_scan_keyboard_interrupt_still_saves_interrupted(sqlite_app, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.run_detection", Mock(side_effect=KeyboardInterrupt))
    saved, checkpoint = snapshots()
    report = run_scan(sqlite_app.url + "/control/vulnerable/search?q=apple", interval=0, checkpoint=checkpoint)
    assert report.status == saved[-1]["collection_status"] == "interrupted"
    assert report.to_dict()["execution_errors"] == []


@pytest.mark.parametrize("runner,path", [
    (run_baseline, "/health"), (run_sqli, "/control/vulnerable/search?q=apple"),
    (run_xss, "/xss/html/raw?q=demo"), (run_exposure, "/"),
])
def test_unexpected_transport_exception_still_counts_the_attempt(monkeypatch, runner, path):
    send = Mock(side_effect=RuntimeError(SECRET))
    monkeypatch.setattr("requests.Session.get", send)
    report = runner("http://127.0.0.1:1" + path, interval=0)
    data = report.to_dict()
    assert data["summary"]["requests_attempted"] == send.call_count == 1
    assert data["collection_status"] == "incomplete"
    assert data["errors"] == [] and len(data["execution_errors"]) == 1


def test_runtime_oserror_is_not_mislabeled_as_checkpoint_error(sqlite_app, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.run_detection", Mock(side_effect=OSError(SECRET)))
    report = run_scan(sqlite_app.url + "/control/vulnerable/search?q=apple", interval=0)
    assert report.status == "incomplete"
    assert "execution_error" in report.stop_reasons
    assert "checkpoint_error" not in report.stop_reasons


@pytest.mark.parametrize("module,assessor", [
    ("sqli", "scanner.modules.sqli.assess"),
    ("xss", "scanner.modules.xss.assess_xss"),
    ("exposure", "scanner.modules.exposure.assess"),
])
def test_keyboard_interrupt_is_not_masked_by_a_broken_assessor(sqlite_app, monkeypatch, module, assessor):
    monkeypatch.setattr("requests.Session.get", Mock(side_effect=KeyboardInterrupt))
    monkeypatch.setattr(assessor, crash)
    # Evita interromper a descoberta; o teste é da finalização do detector.
    monkeypatch.setattr("scanner.pipeline.crawl", lambda report, client: None)
    monkeypatch.setattr("scanner.pipeline.collect_targets", lambda report: report.targets.append({
        "url": sqlite_app.url + "/control/vulnerable/search?q=apple", "endpoint": sqlite_app.url,
        "module": module, "parameter": None if module == "exposure" else "q", "context": "like",
        "profile": "config", "file_path": ".env", "status": "pending", "sources": [{"kind": "manual"}],
    }))
    report = run_scan(sqlite_app.url + "/", modules=(module,), interval=0)
    assert report.status == "interrupted"
    assert len(report.requests) == 1


def test_keyboard_interrupt_during_final_checkpoint_returns_130(http_lab, monkeypatch, tmp_path):
    from scanner.reporter import write_reports

    site = http_lab.start(lambda _: http_lab.reply())
    interrupted = False

    def save(report, destination, **options):
        nonlocal interrupted
        if report.finished_at is not None and not interrupted:
            interrupted = True
            raise KeyboardInterrupt
        return write_reports(report, destination, **options)

    monkeypatch.setattr("main.write_reports", save)
    output = tmp_path / "interrupted.json"
    assert main(["scan", site.url, "--interval", "0", "--output", str(output)]) == 130
    assert json.loads(output.read_text(encoding="utf-8"))["collection_status"] == "interrupted"
