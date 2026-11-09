"""Extract only verified individual assessments; the catalog supplies ground truth."""
from urllib.parse import urlsplit
from scanner.reporter import read_verified_reports
from experiments.evaluation.compare_baseline import predict
from experiments.evaluation.metrics import OUTCOMES


def verified(path, result):
    data, findings = read_verified_reports(path, expected_run_id=result["run_id"])
    if data["snapshot_id"] != result["snapshot_id"]:
        raise ValueError("Snapshot mismatch")
    return data, findings


def units_from(data):
    analyses = data.get("analyses", []) if data.get("mode") == "scan" else [data]
    for analysis in analyses:
        for item in analysis.get("parameter_results", []):
            yield analysis, item, item["parameter"], None
        for item in analysis.get("exposure_results", []):
            yield analysis, item, None, urlsplit(item["url"]).path


def extract(case, job, result, data):
    available = list(units_from(data)) if data is not None else []
    declared = case["units"]
    if not declared and data is not None:
        # Automatic targets are descriptive, not an invented full-app oracle.
        declared = [dict(unit_id=f'{case["case_id"]}-observed-{i+1:03d}', module=a["mode"], truth="unknown",
                         parameter=p, file_path=f, stratum="integration", _index=i)
                    for i, (a, _, p, f) in enumerate(available)]
    rows = []
    for unit in declared:
        matched = None
        for index, candidate in enumerate(available):
            analysis, item, parameter, file_path = candidate
            if "_index" in unit:
                ok = index == unit["_index"]
            else:
                ok = analysis["mode"] == unit["module"] and (parameter == unit["parameter"] if unit["parameter"] is not None else
                    bool(file_path and file_path.endswith('/' + unit["file_path"])))
            if ok:
                matched = candidate
                break
        row = {**{k: job[k] for k in ("evaluation_id", "case_id", "condition", "repetition")},
            "unit_id": unit["unit_id"], "domain": case.get("domain", "controlled"), "module": unit["module"],
            "truth": unit["truth"], "stratum": unit["stratum"], "outcome": "not_evaluated",
            "baseline": "not_evaluated", "reason": "assessment_missing" if result.get("reason") == "observed" else result.get("reason", "assessment_missing"),
            "wall_seconds": result.get("wall_seconds"), "requests": None,
            "return_code": result.get("return_code"), "checks": {}, "failed_checks": [],
            "browser_confirmed": None, "browser_status": None, "evidence_request_ids": [],
            "reference_id": None, "required_ids": [], "baseline_complete": False, "observations": []}
        if matched:
            analysis, item, _, _ = matched
            if item.get("assessment") is None:
                rows.append(row)
                continue
            outcome = item["assessment"].get("outcome")
            if outcome not in OUTCOMES - {"not_evaluated"} or outcome == "reflected_safe" and unit["module"] != "xss":
                raise ValueError("Invalid outcome in verified report")
            ids = item["evidence_request_ids"]
            responses = [r for r in analysis.get("responses", []) if r["request_id"] in ids]
            probes = [p for p in analysis.get("probes", []) if p["request_id"] in ids]
            roles = {p["role"]: p["request_id"] for p in (responses if unit["module"] == "exposure" else probes)}
            reference = roles.get("reference_1" if unit["module"] == "exposure" else "baseline_1")
            end_role = "control_2" if unit["module"] == "exposure" else "recovery"
            complete = end_role in roles and set(ids) <= {r["request_id"] for r in responses}
            observations = [{k: r[k] for k in ("request_id", "status_code", "size_bytes", "body_sha256")} for r in responses]
            checks = item["assessment"].get("checks", {})
            browser = item["assessment"].get("browser_evidence", {})
            attempted = {r["request_id"] for r in responses} | {e["request_id"] for e in analysis.get("errors", []) if e["request_id"] in ids}
            row.update(outcome=outcome, baseline=predict(observations, reference, ids, complete),
                reason="observed", requests=len(attempted), checks=checks,
                failed_checks=[k for k, v in checks.items() if not v], browser_confirmed=bool(browser.get("confirmed")),
                browser_status=browser.get("status"), evidence_request_ids=ids, observations=observations,
                reference_id=reference, required_ids=ids, baseline_complete=complete)
        rows.append(row)
    return rows
