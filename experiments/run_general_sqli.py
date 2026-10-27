"""Experimento reproduzível dos perfis e formatos SQLi, sem alterar resultados."""

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
from urllib.parse import urlsplit

from experiments.run_control import health
from scanner.core import run_sqli
from scanner.models import utc_now
from scanner.reporter import write_json
from scanner.targets import validate_target


@dataclass(frozen=True)
class Case:
    name: str
    path_query: str
    expected: dict[str, str]
    parameter: str | None = None
    context: str = "like"
    all_parameters: bool = False


CASES = (
    Case("legacy-vulnerable", "/control/vulnerable/search?q=apple", {"q": "confirmed"}),
    Case("legacy-safe", "/control/safe/search?q=apple", {"q": "not_detected"}),
    Case("json-vulnerable", "/general/json/vulnerable?term=apple&lang=en", {"term": "confirmed"}, "term"),
    Case("json-safe", "/general/json/safe?term=apple&lang=en", {"term": "not_detected"}, "term"),
    Case("html-vulnerable", "/general/html/vulnerable?search=apple&lang=en", {"search": "confirmed"}, "search"),
    Case("html-safe", "/general/html/safe?search=apple&lang=en", {"search": "not_detected"}, "search"),
    Case("text-vulnerable", "/general/text/vulnerable?keyword=apple&lang=en", {"keyword": "confirmed"}, "keyword"),
    Case("text-safe", "/general/text/safe?keyword=apple&lang=en", {"keyword": "not_detected"}, "keyword"),
    Case("quoted-vulnerable", "/general/quoted/vulnerable?item=Apple+Demo", {"item": "confirmed"}, context="quoted"),
    Case("quoted-safe", "/general/quoted/safe?item=Apple+Demo", {"item": "not_detected"}, context="quoted"),
    Case("multiple-parameters", "/general/html/vulnerable?search=apple&lang=en", {"search": "confirmed", "lang": "not_detected"}, all_parameters=True),
    Case("unstable", "/general/html/unstable?search=apple", {"search": "inconclusive"}),
    Case("error-page", "/general/html/error?search=apple", {"search": "inconclusive"}),
    Case("wrong-context", "/general/json/vulnerable?term=apple", {"term": "suspected"}, context="quoted"),
)


def run_experiment(base_url, output_dir, *, case_names=None, juice_shop_url=None, interval=0.2):
    base = validate_target(base_url)
    parts = urlsplit(base)
    if parts.path != "/" or parts.query:
        raise ValueError("Use somente a origem local do laboratório em --base-url.")
    if juice_shop_url:
        juice_shop_url = validate_target(juice_shop_url)
    names = set(case_names or (case.name for case in CASES))
    if names - {case.name for case in CASES}:
        raise ValueError("Caso desconhecido.")
    cases = [case for case in CASES if case.name in names]
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    summary = {"experiment": "general_sqli", "started_at": utc_now(), "dataset_before": health(base.rstrip("/")), "runs": []}
    if "error" not in summary["dataset_before"]:
        targets = [(case, base.rstrip("/") + case.path_query) for case in cases]
        if juice_shop_url:
            targets.append((Case("juice-shop", "", {"q": "confirmed"}, "q"), juice_shop_url))
        for case, target in targets:
            report = run_sqli(target, parameter=case.parameter, all_parameters=case.all_parameters,
                              context=case.context, max_requests=20 if case.all_parameters else 10, interval=interval)
            destination = write_json(report, output / (case.name + ".json"))
            outcomes = {result.parameter: result.assessment.outcome for result in report.parameter_results}
            summary["runs"].append({
                "case": case.name, "target": report.target, "context": case.context,
                "outcomes": outcomes, "expected_outcomes": case.expected,
                "expectation_matched": outcomes == case.expected, "transport_errors": len(report.errors),
                "requests_attempted": report.to_dict()["summary"]["requests_attempted"],
                "findings": len(report.findings), "report": destination.name,
            })
    summary["dataset_after"] = health(base.rstrip("/"))
    summary["dataset_unchanged"] = "error" not in summary["dataset_before"] and summary["dataset_before"] == summary["dataset_after"]
    summary["expectations_matched"] = bool(summary["runs"]) and all(run["expectation_matched"] for run in summary["runs"])
    summary["status"] = "completed" if (
        len(summary["runs"]) == len(cases) + bool(juice_shop_url) and summary["dataset_unchanged"]
        and all(not run["transport_errors"] for run in summary["runs"])
    ) else "incomplete"
    summary["finished_at"] = utc_now()
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validação real da generalização SQLi em JSON, HTML e texto.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8001")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/general-sqli"))
    parser.add_argument("--case", action="append", choices=[case.name for case in CASES])
    parser.add_argument("--juice-shop-url", help="URL GET local de regressão do Juice Shop, opcional")
    args = parser.parse_args(argv)
    try:
        summary = run_experiment(args.base_url, args.output_dir, case_names=args.case, juice_shop_url=args.juice_shop_url)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Erro no experimento: {error}\n")
    for run in summary["runs"]:
        print(f"{run['case']}: {run['outcomes']}; {run['requests_attempted']} requisições; {run['report']}")
    print(f"Base preservada: {summary['dataset_unchanged']}; expectativas correspondem ao observado: {summary['expectations_matched']}")
    print(f"Resumo: {args.output_dir / 'summary.json'}")
    return 0 if summary["status"] == "completed" and summary["expectations_matched"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
