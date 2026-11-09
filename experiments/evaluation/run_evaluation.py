"""Versioned evaluator CLI; only run contacts authorized loopback laboratories."""
import argparse
from contextlib import contextmanager
from collections import Counter
from datetime import datetime, timezone
import importlib.metadata
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import threading
import time
from uuid import uuid4
import zipfile

from experiments.evaluation import __version__
from experiments.evaluation.common import ROOT, CASES, PROTOCOL, ARCHIVE, ARCHIVE_SHA, digest, put, load, source_state, seal
from experiments.sqlite_control import ControlServer
from scanner.http_client import HttpClient
from scanner.private_files import private_directory
from scanner.reporter import read_verified_reports, manifest_path
from scanner.xss_browser import browser_path
from scanner.terminal import SafeArgumentParser, safe_print

FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def now():
    return datetime.now(timezone.utc).isoformat()


def environment():
    browser = browser_path()
    node = shutil.which("node")
    from scanner import __version__ as product_version
    browser_version = None
    if browser and os.name == "nt":
        command = "(Get-Item -LiteralPath '" + browser.replace("'", "''") + "').VersionInfo.FileVersion"
        browser_version = subprocess.check_output(["powershell", "-NoProfile", "-Command", command], text=True).strip()
    return dict(python=sys.version, platform=sys.platform, tool_version=__version__, product_version=product_version,
        original_juice_database_sha256=digest(ROOT / "lab/juice-shop_20.3.0/data/juiceshop.sqlite") if (ROOT / "lab/juice-shop_20.3.0/data/juiceshop.sqlite").exists() else None,
        packages={d.metadata["Name"]: d.version for d in importlib.metadata.distributions()},
        browser_available=bool(browser and node), browser_version=browser_version,
        node_version=subprocess.check_output([node, "--version"], text=True).strip() if node else None,
        head=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        dirty=subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).splitlines())


def prepare(base=None):
    base = Path(base or ROOT / "reports/evaluation")
    base.mkdir(parents=True, exist_ok=True)
    evaluation_id = str(uuid4())
    directory = private_directory(base / evaluation_id)
    catalog = load(CASES)
    put(directory / "catalog.json", catalog)
    (directory / "protocol.md").write_bytes(PROTOCOL.read_bytes())
    put(directory / "environment.json", environment())
    state = source_state()
    put(directory / "source-state.json", state)
    jobs = []
    for repetition in range(1, 4):
        for case in catalog["cases"]:
            for condition in case["conditions"]:
                slot = f'{case["case_id"]}-{condition}-r{repetition}'
                job = dict(evaluation_id=evaluation_id, case_id=case["case_id"], condition=condition,
                           repetition=repetition, slot=slot)
                jobs.append(job)
                put(directory / "runs" / slot / "job.json", job)
    put(directory / "campaign.json", dict(evaluation_id=evaluation_id, prepared_at=now(),
        protocol_version="1.0.0", catalog_version=catalog["catalog_version"], tool_version=__version__,
        protocol_sha256=digest(directory / "protocol.md"), catalog_sha256=digest(directory / "catalog.json"),
        code_state_id=state["sha256"], planned_runs=len(jobs), jobs=jobs))
    return directory


@contextmanager
def control():
    server = ControlServer(0)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=10)
        server.server_close()
        if thread.is_alive():
            raise RuntimeError("Control server did not stop")


def kill_owned(process):
    if process.poll() is None:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=FLAGS, check=False)
        else:
            process.kill()
        process.wait(timeout=15)


def listening():
    """Read TCP ownership without probing an unidentified service."""
    command = "Get-NetTCPConnection -State Listen -LocalPort 3000 -ErrorAction SilentlyContinue | ForEach-Object { $_.LocalAddress + '|' + $_.OwningProcess }"
    output = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, creationflags=FLAGS, check=False).stdout
    return [line.strip().split("|") for line in output.splitlines() if "|" in line]


def clone_juice(directory):
    if digest(ARCHIVE) != ARCHIVE_SHA:
        raise ValueError("Juice archive integrity mismatch")
    runtime = private_directory(directory / "runtime")
    checked = 0
    with zipfile.ZipFile(ARCHIVE) as archive:
        for info in archive.infolist():
            relative = PurePosixPath(info.filename)
            if relative.is_absolute() or ".." in relative.parts or "\\" in info.filename:
                raise ValueError("Invalid archive path")
            target = (runtime / info.filename).resolve()
            if not target.is_relative_to(runtime.resolve()):
                raise ValueError("Archive path escaped runtime")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            import hashlib
            expected = hashlib.sha256()
            with archive.open(info) as source, target.open("xb") as out:
                for block in iter(lambda: source.read(1024*1024), b""):
                    expected.update(block)
                    out.write(block)
            if digest(target) != expected.hexdigest():
                raise ValueError("Extracted file integrity mismatch")
            checked += 1
    put(directory / "clone-integrity.json", dict(archive_sha256=ARCHIVE_SHA, checked=checked,
        mismatches=0, version=load(runtime / "juice-shop_20.3.0/package.json")["version"]))
    return runtime / "juice-shop_20.3.0"


@contextmanager
def juice(clone, directory, repetition):
    if listening():
        raise RuntimeError("port_occupied")
    node = shutil.which("node")
    if not node:
        raise RuntimeError("node_unavailable")
    process = subprocess.Popen([node, "--require", str(ROOT / "scripts/loopback-only.cjs"), "build/app"],
        cwd=clone, env={**os.environ, "PORT": "3000"}, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=FLAGS)
    try:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("service_exited")
            sockets = listening()
            if sockets:
                if any(address != "127.0.0.1" or int(pid) != process.pid for address, pid in sockets):
                    raise RuntimeError("unexpected_listener")
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("startup_timeout")
        with HttpClient(max_requests=1, interval=0) as client:
            response = client.get("http://127.0.0.1:3000/rest/admin/application-version")
            import json
            version = json.loads(response.body).get("version")
            if response.status_code != 200 or version != "20.3.0":
                raise RuntimeError("service_identity_mismatch")
        put(directory / f"juice-preflight-r{repetition}.json", dict(repetition=repetition, pid=process.pid,
            listener="127.0.0.1:3000", version=version, requests=1, node_version=subprocess.check_output([node, "--version"], text=True).strip()))
        yield "http://127.0.0.1:3000"
    finally:
        kill_owned(process)


def describe_scan(data):
    discovery = data.get("discovery", {})
    endpoints = discovery.get("endpoints", [])
    return dict(pages=discovery.get("summary", {}).get("pages_fetched"), endpoints=len(endpoints),
        parameters=len({(e["endpoint"], p["name"]) for e in endpoints for p in e.get("parameters", [])}),
        targets=len(data.get("targets", [])), target_statuses=dict(Counter(t["status"] for t in data.get("targets", []))),
        ignored_reasons=dict(Counter(t["reason"] for t in data.get("ignored_targets", []))),
        requests_by_phase=dict(Counter(r["phase"] for r in data.get("requests", []))),
        requests_by_module=dict(Counter(r.get("module", "discovery") for r in data.get("requests", []))),
        configured_file_targets=sum(t.get("module") == "exposure" for t in data.get("targets", [])),
        known_search_discovered=any('/rest/products/search' == __import__('urllib.parse', fromlist=['urlsplit']).urlsplit(u).path
                                    for e in endpoints for u in e.get("observed_urls", [])),
        known_search_analyzed=any(a["mode"] == "sqli" and '/rest/products/search' == __import__('urllib.parse', fromlist=['urlsplit']).urlsplit(a["target"]).path for a in data.get("analyses", [])),
        analysis_summary=data.get("analysis_summary"), collection_status=data.get("collection_status"),
        stop_reasons=data.get("stop_reasons", []))


def execute(case, job, base, directory, db=None):
    output = directory / "runs" / job["slot"] / "full.json"
    args = [sys.executable, str(ROOT / "main.py")]
    if case["module"] == "scan":
        args += ["scan", base + case["path"], "--modules", "sqli", "xss", "exposure", "--exposure-profiles", "config", "backup", "repository"]
    else:
        args += [base + case["path"], "--module", case["module"]]
        if case["module"] == "exposure":
            args += ["--exposure-profiles", case["profile"]]
        elif case["module"] == "sqli":
            args += ["--sqli-context", case["context"]]
            args += ["--all-parameters"] if case.get("all_parameters") else ["--parameter", case["units"][0]["parameter"]]
        elif job["condition"] == "browser":
            args += ["--xss-browser"]
    args += ["--max-requests", str(case["budget"]), "--evidence-profile", "restricted", "--output", str(output)]
    before = db.manifest() if db else None
    started_at = now()
    start = time.monotonic()
    process = subprocess.Popen(args, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, creationflags=FLAGS)
    try:
        code = process.wait()
    except KeyboardInterrupt:
        kill_owned(process)
        raise
    result = dict(started_at=started_at, finished_at=now(), return_code=code, wall_seconds=time.monotonic()-start,
                  reason="report_unavailable", requests=None, dataset_before=before, dataset_after=db.manifest() if db else None,
                  dataset_unchanged=before == db.manifest() if db else None)
    pointer = manifest_path(output)
    try:
        data, _ = read_verified_reports(pointer)
        result.update(run_id=data["run_id"], snapshot_id=data["snapshot_id"],
            manifest_sha256=digest(pointer), manifest=pointer.relative_to(directory).as_posix(),
            requests=data["summary"].get("requests_used", data["summary"].get("requests_attempted")), reason="observed",
            scan_seconds=(datetime.fromisoformat(data["finished_at"])-datetime.fromisoformat(data["started_at"])).total_seconds() if data.get("finished_at") else None)
        if case["module"] == "scan":
            result["workflow"] = describe_scan(data)
    except (ValueError, OSError, KeyError, TypeError):
        result["reason"] = "invalid_evidence" if pointer.exists() else "report_unavailable"
    if source_state()["sha256"] != load(directory / "campaign.json")["code_state_id"]:
        result["reason"] = "code_state_changed"
    put(output.parent / "result.json", result)
    return result


def run(directory):
    directory = Path(directory).resolve()
    campaign = load(directory / "campaign.json")
    if (directory / "finished.json").exists() or (directory / "started.json").exists():
        raise ValueError("Campaign cannot be overwritten or retried")
    if source_state()["sha256"] != campaign["code_state_id"] or digest(directory / "protocol.md") != campaign["protocol_sha256"] or digest(directory / "catalog.json") != campaign["catalog_sha256"]:
        raise ValueError("Frozen campaign inputs changed")
    put(directory / "started.json", dict(started_at=now()))
    catalog = {c["case_id"]: c for c in load(directory / "catalog.json")["cases"]}
    has_browser = environment()["browser_available"]
    done = 0
    interrupted = False
    stop_reason = None
    try:
        for job in campaign["jobs"]:
            case = catalog[job["case_id"]]
            if case.get("domain") == "juice":
                continue
            if source_state()["sha256"] != campaign["code_state_id"]:
                raise RuntimeError("code_state_changed")
            if job["condition"] == "browser" and not has_browser:
                put(directory / "runs" / job["slot"] / "result.json", dict(reason="browser_unavailable"))
                continue
            with control() as (server, base):
                result = execute(case, job, base, directory, server.database)
            done += 1
            safe_print(f'{done}/165 {job["slot"]}: {result["reason"]}', flush=True)
            if source_state()["sha256"] != campaign["code_state_id"]:
                raise RuntimeError("code_state_changed")
        try:
            clone = directory / "runtime/juice-shop_20.3.0" if (directory / "clone-integrity.json").exists() else clone_juice(directory)
            for repetition in range(1, 4):
                selected = [j for j in campaign["jobs"] if j["repetition"] == repetition and catalog[j["case_id"]].get("domain") == "juice"]
                try:
                    with juice(clone, directory, repetition) as base:
                        for job in selected:
                            if source_state()["sha256"] != campaign["code_state_id"]:
                                raise RuntimeError("code_state_changed")
                            result = execute(catalog[job["case_id"]], job, base, directory)
                            done += 1
                            safe_print(f'{done}/165 {job["slot"]}: {result["reason"]}', flush=True)
                except (RuntimeError, OSError, ValueError):
                    for job in selected:
                        p = directory / "runs" / job["slot"] / "result.json"
                        if not p.exists():
                            put(p, dict(reason="juice_preflight_failed"))
        except (RuntimeError, OSError, ValueError):
            for job in campaign["jobs"]:
                p = directory / "runs" / job["slot"] / "result.json"
                if catalog[job["case_id"]].get("domain") == "juice" and not p.exists():
                    put(p, dict(reason="juice_clone_failed"))
    except KeyboardInterrupt:
        interrupted = True
        stop_reason = "interrupted"
    except Exception:
        stop_reason = "execution_stopped"
    finally:
        old_db = ROOT / "lab/juice-shop_20.3.0/data/juiceshop.sqlite"
        original_unchanged = (digest(old_db) if old_db.exists() else None) == load(directory / "environment.json")["original_juice_database_sha256"]
        put(directory / "finished.json", dict(finished_at=now(), executed=done, interrupted=interrupted, stop_reason=stop_reason,
                                             original_juice_database_unchanged=original_unchanged))
        seal(directory)
    return done


def main(argv=None):
    parser = SafeArgumentParser(description="PK-F3 independent experimental evaluator")
    parser.add_argument("command", choices=["prepare", "run", "analyze", "export", "verify"])
    parser.add_argument("directory", nargs="?", type=Path)
    parser.add_argument("--analysis", type=Path)
    args = parser.parse_args(argv)
    if args.command == "prepare":
        directory = prepare(args.directory)
        try:
            clone_juice(directory)
        except (OSError, ValueError):
            put(directory / "clone-unavailable.json", dict(reason="clone_preflight_failed"))
        safe_print(directory)
        return 0
    if args.directory is None:
        parser.error("directory is required")
    if args.command == "run":
        run(args.directory)
    else:
        from experiments.evaluation.generate_report import analyze, export, verify
        if args.command == "analyze":
            safe_print(analyze(args.directory))
        elif args.command == "export":
            safe_print(export(args.directory, args.analysis))
        else:
            verify(args.directory)
            safe_print("Experiment verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
