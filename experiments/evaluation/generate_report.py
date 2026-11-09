"""Offline analysis/export; no target access and no reclassification of ProbeKit."""
from collections import Counter
import csv
import io
import os
from pathlib import Path
import shutil
from uuid import uuid4

from experiments.evaluation.common import ROOT, encoded, put, load, digest, confined, seal, verify_seal, source_state
from experiments.evaluation.extract import extract, verified, units_from
from experiments.evaluation.metrics import grouped, repeatability
from experiments.evaluation.compare_baseline import predict
from scanner.reporter import write_reports, read_verified_reports, _Snapshot
from scanner.privacy import EvidencePolicy

ANALYSIS_VERSION = "1.0.3"


def timing_points(rows):
    """Direct runs only; integrated wall times cannot be attributed to one module."""
    return list({(r["case_id"],r["condition"],r["repetition"]):r for r in rows
                 if r["domain"] == "controlled" and r["wall_seconds"] is not None}.values())


def csv_file(path, rows, columns):
    text = io.StringIO(newline="")
    writer = csv.DictWriter(text, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerows({key: row.get(key) for key in columns} for row in rows)
    Path(path).write_bytes(text.getvalue().encode("utf-8"))


def dataset(directory):
    directory = Path(directory).resolve()
    sealed = verify_seal(directory)
    campaign = load(directory / "campaign.json")
    if digest(directory / "protocol.md") != campaign["protocol_sha256"] or digest(directory / "catalog.json") != campaign["catalog_sha256"]:
        raise ValueError("Protocol/catalog identity mismatch")
    cases = {c["case_id"]: c for c in load(directory / "catalog.json")["cases"]}
    rows, workflows, reports = [], [], []
    for job in campaign["jobs"]:
        case = cases[job["case_id"]]
        name = f'runs/{job["slot"]}/result.json'
        result = load(directory / name) if name in sealed["files"] else dict(reason="not_executed")
        data = None
        if result.get("reason") == "observed":
            try:
                pointer = confined(directory, result["manifest"])
                if digest(pointer) != result["manifest_sha256"]:
                    raise ValueError("Pointer hash mismatch")
                data, _ = verified(pointer, result)
                reports.append((job, result, data))
            except (OSError, ValueError, KeyError, TypeError):
                result = {**result, "reason": "invalid_evidence"}
        rows.extend(extract(case, job, result, data))
        workflows.append({**{k: job[k] for k in ("case_id", "condition", "repetition", "slot")},
            **{k: result.get(k) for k in ("reason", "requests", "wall_seconds", "scan_seconds", "return_code", "dataset_unchanged", "workflow")},
            "run_id": result.get("run_id"), "snapshot_id": result.get("snapshot_id")})
    return campaign, rows, workflows, reports


def figures(directory, groups, rows):
    os.environ.setdefault("MPLCONFIGDIR", str(ROOT / "reports/phase3-mpl-cache"))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "DejaVu Sans", "svg.hashsalt": "PK-F3-1.0.0"})
    directory.mkdir()
    selected = [g for g in groups if g["domain"] == "controlled" and g["stratum"] == "principal"]
    labels = [g["module"] + "/" + g["condition"] for g in selected]
    keys = ["TP", "FP", "TN", "FN", "suspected", "inconclusive", "not_evaluated"]
    fig, ax = plt.subplots(figsize=(10, 5))
    bottom = [0]*len(selected)
    for key in keys:
        values = [g["A"]["counts"][key] for g in selected]
        ax.bar(labels, values, bottom=bottom, label=key)
        bottom = [a+b for a, b in zip(bottom, values)]
    ax.set(ylabel="Evaluation slots (3 repetitions)", title="ProbeKit: outcomes and abstentions, principal stratum")
    ax.legend(ncol=4, fontsize=8)
    fig.tight_layout()
    for fmt in ("png", "svg"):
        fig.savefig(directory / ("outcomes."+fmt), dpi=160, metadata={"Date": None} if fmt == "svg" else {})
    plt.close(fig)
    fig, axes = plt.subplots(1, max(1, len(selected)), figsize=(4*max(1, len(selected)), 4), squeeze=False)
    for ax, group in zip(axes[0], selected):
        c = group["A"]["counts"]
        matrix = [[c["TP"], c["FN"]], [c["FP"], c["TN"]]]
        ax.imshow(matrix, cmap="Blues")
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(matrix[i][j]), ha="center", va="center")
        ax.set(xticks=[0,1], xticklabels=["Positive", "Negative"], yticks=[0,1], yticklabels=["Vulnerable", "Safe"],
               title=group["module"]+"/"+group["condition"])
        ax.set_xlabel(f'Abstentions: {c["suspected"]+c["inconclusive"]}; not evaluated: {c["not_evaluated"]}')
    fig.tight_layout()
    for fmt in ("png", "svg"):
        fig.savefig(directory / ("matrices."+fmt), dpi=160, metadata={"Date": None} if fmt == "svg" else {})
    plt.close(fig)
    fig, ax = plt.subplots(figsize=(10,5))
    x = range(len(selected)); width=.35
    ax.bar([i-width/2 for i in x], [g["A"]["counts"]["FP"] for g in selected], width, label="ProbeKit confirmed FP")
    ax.bar([i+width/2 for i in x], [g["B"]["counts"]["FP"] for g in selected], width, label="Heuristic positive FP")
    ax.set(xticks=list(x), xticklabels=labels, ylabel="False-positive predictions", title="Same-evidence comparison; B is not confirmation")
    ax.legend();fig.tight_layout()
    for fmt in ("png", "svg"):
        fig.savefig(directory / ("comparison."+fmt), dpi=160, metadata={"Date": None} if fmt == "svg" else {})
    plt.close(fig)
    # One point per job; multi-unit cases must not duplicate process durations.
    unique = timing_points(rows)
    pairs = sorted({(r["module"], r["condition"]) for r in unique})
    fig, ax = plt.subplots(figsize=(10,5))
    for i, pair in enumerate(pairs):
        values = [r["wall_seconds"] for r in unique if (r["module"],r["condition"])==pair]
        ax.scatter([i]*len(values), values, alpha=.5)
    ax.set(xticks=list(range(len(pairs))), xticklabels=["/".join(p) for p in pairs], ylabel="Process wall time (seconds)", title="Direct controlled runs; no confidence interval")
    fig.tight_layout()
    for fmt in ("png", "svg"):
        fig.savefig(directory / ("timings."+fmt), dpi=160, metadata={"Date": None} if fmt == "svg" else {})
    plt.close(fig)


def analyze(directory):
    directory = Path(directory).resolve()
    campaign, rows, workflows, _ = dataset(directory)
    analysis_id = str(uuid4())
    destination = directory / "analyses" / analysis_id
    destination.mkdir(parents=True)
    groups = grouped(rows)
    put(destination / "rows.json", rows)
    put(destination / "workflows.json", workflows)
    put(destination / "metrics.json", dict(evaluation_id=campaign["evaluation_id"], analysis_id=analysis_id,
        analysis_version=ANALYSIS_VERSION, groups=groups, planned_runs=campaign["planned_runs"],
        verified_runs=sum(w["reason"]=="observed" for w in workflows),
        scanner_requests=sum(w["requests"] for w in workflows if w["requests"] is not None),
        unknown_request_runs=sum(w["requests"] is None for w in workflows),
        not_evaluated_runs=[w["slot"] for w in workflows if w["reason"]!="observed"]))
    put(destination / "repeatability.json", repeatability(rows))
    put(destination / "analysis-source-state.json", source_state())
    columns = ["evaluation_id","case_id","condition","repetition","unit_id","domain","module","truth","stratum","outcome","baseline","reason","requests","wall_seconds","browser_confirmed","browser_status"]
    csv_file(destination / "results.csv", rows, columns)
    matrices = [{**{k:g[k] for k in ("domain","module","condition","stratum")}, "method": method,
                 **g[method]["counts"]} for g in groups for method in ("A","B")]
    csv_file(destination / "confusion-matrices.csv", matrices, ["domain","module","condition","stratum","method","TP","FP","TN","FN","suspected","inconclusive","not_evaluated","outside_binary"])
    csv_file(destination / "comparison.csv", rows, ["case_id","condition","repetition","unit_id","truth","outcome","baseline"])
    figures(destination / "figures", groups, rows)
    seal(destination)
    return destination


def export(directory, analysis):
    directory = Path(directory).resolve()
    if analysis is None:
        raise ValueError("Explicit analysis directory required")
    analysis = Path(analysis).resolve()
    if not analysis.is_relative_to(directory / "analyses"):
        raise ValueError("Analysis outside campaign")
    verify_seal(analysis)
    campaign, rows, workflows, reports = dataset(directory)
    if load(analysis / "rows.json") != rows or load(analysis / "workflows.json") != workflows:
        raise ValueError("Analysis inputs mismatch")
    base = ROOT / "docs/evidencias/fase3"
    base.mkdir(parents=True, exist_ok=True)
    destination = base / (campaign["evaluation_id"] + "-" + analysis.name)
    destination.mkdir()
    for file in analysis.rglob("*"):
        if file.is_file() and file.name != "seal.json":
            target = destination / "analysis" / file.relative_to(analysis)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(file, target)
    for source, target in (("protocol.md","protocol.md"),("catalog.json","cases.json"),("source-state.json","source-state.json")):
        shutil.copyfile(directory / source, destination / target)
    env = load(directory / "environment.json")
    put(destination / "environment.json", {k:v for k,v in env.items() if k != "dirty"})
    registry = []
    for job, original, data in reports:
        output = destination / "evidence" / job["slot"] / "full.json"
        write_reports(_Snapshot(data), output, policy=EvidencePolicy("shareable"))
        pointer = output.with_name("full.json.manifest.json")
        public, _ = read_verified_reports(pointer, expected_run_id=original["run_id"])
        registry.append(dict(slot=job["slot"], run_id=public["run_id"], snapshot_id=public["snapshot_id"],
            source_snapshot_id=original["snapshot_id"], manifest=pointer.relative_to(destination).as_posix()))
    put(destination / "registry.json", dict(evaluation_id=campaign["evaluation_id"], analysis_id=analysis.name,
        catalog_sha256=digest(destination / "cases.json"), protocol_sha256=digest(destination / "protocol.md"), reports=registry))
    seal(destination)
    verify(destination)
    return destination


def verify(directory):
    directory = Path(directory).resolve()
    verify_seal(directory)
    registry_path = directory / "registry.json"
    if not registry_path.exists():
        dataset(directory)
        return
    registry = load(registry_path)
    if digest(directory / "cases.json") != registry["catalog_sha256"] or digest(directory / "protocol.md") != registry["protocol_sha256"]:
        raise ValueError("Public protocol/catalog mismatch")
    rows = load(directory / "analysis/rows.json")
    metrics = load(directory / "analysis/metrics.json")
    workflows = load(directory / "analysis/workflows.json")
    if (metrics["evaluation_id"] != registry["evaluation_id"]
            or metrics["analysis_id"] != registry["analysis_id"]
            or any(r["evaluation_id"] != registry["evaluation_id"] for r in rows)):
        raise ValueError("Experimental campaign/analysis identity mismatch")
    by_workflow = {w["slot"]:w for w in workflows}
    if len(by_workflow) != len(workflows):
        raise ValueError("Duplicate execution slot")
    by_slot = {}
    for item in registry["reports"]:
        workflow = by_workflow.get(item["slot"])
        if (item["slot"] in by_slot or workflow is None or workflow["reason"] != "observed"
                or workflow["run_id"] != item["run_id"]
                or workflow["snapshot_id"] != item["source_snapshot_id"]):
            raise ValueError("Public report differs from original execution identity")
        data, _ = read_verified_reports(confined(directory, item["manifest"]), expected_run_id=item["run_id"])
        if data["snapshot_id"] != item["snapshot_id"] or data["evidence_profile"] != "shareable":
            raise ValueError("Public evidence identity mismatch")
        by_slot[item["slot"]] = data
    cases = {c["case_id"]: c for c in load(directory / "cases.json")["cases"]}
    if grouped(rows) != metrics["groups"]:
        raise ValueError("Public metrics do not reproduce")
    for row in rows:
        case = cases[row["case_id"]]
        declared = next((u for u in case["units"] if u["unit_id"] == row["unit_id"]), None)
        if declared and (row["truth"] != declared["truth"] or row["stratum"] != declared["stratum"]):
            raise ValueError("Row differs from independent oracle")
        if not declared and row["truth"] != "unknown":
            raise ValueError("Undeclared oracle")
        if row["outcome"] != "not_evaluated":
            data = by_slot[f'{row["case_id"]}-{row["condition"]}-r{row["repetition"]}']
            candidates = [(a, i) for a, i, _, _ in units_from(data) if a["mode"] == row["module"] and i["evidence_request_ids"] == row["evidence_request_ids"]]
            if len(candidates) != 1 or candidates[0][1]["assessment"]["outcome"] != row["outcome"]:
                raise ValueError("Row differs from scanner assessment")
            a, _ = candidates[0]
            observations = [{k:r[k] for k in ("request_id","status_code","size_bytes","body_sha256")} for r in a["responses"] if r["request_id"] in row["evidence_request_ids"]]
            if observations != row["observations"]:
                raise ValueError("Row observations differ from scanner evidence")
            roles = {p["role"]:p["request_id"] for p in (a["responses"] if row["module"]=="exposure" else a["probes"]) if p["request_id"] in row["evidence_request_ids"]}
            reference = roles.get("reference_1" if row["module"]=="exposure" else "baseline_1")
            complete = ("control_2" if row["module"]=="exposure" else "recovery") in roles and set(row["evidence_request_ids"]) <= {r["request_id"] for r in observations}
            if row["required_ids"] != row["evidence_request_ids"] or row["reference_id"] != reference or row["baseline_complete"] != complete:
                raise ValueError("Baseline binding differs from collected plan")
        if row["outcome"] != "not_evaluated" and predict(row["observations"], row["reference_id"], row["required_ids"], row["baseline_complete"]) != row["baseline"]:
            raise ValueError("Baseline does not reproduce")
