"""Avalia os dois endpoints com o mesmo scanner, sem alterar a classificação."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import platform
from urllib.parse import urlsplit

from experiments.sqlite_control import SAFE_PATH, VULNERABLE_PATH
from scanner import __version__
from scanner.core import run_sqli
from scanner.http_client import HttpClient, HttpClientError
from scanner.models import utc_now
from scanner.reporter import write_json
from scanner.targets import validate_target


def health(base_url: str) -> dict:
    try:
        with HttpClient(max_requests=1) as client:
            response = client.get(base_url + "/health")
        data = json.loads(response.body)
        if (response.status_code != 200 or not isinstance(data, dict)
                or data.get("application") != "webvuln-sqlite-control"
                or not isinstance(data.get("dataset_sha256"), str)):
            raise ValueError("Resposta incompatível com o laboratório de controle.")
        return data
    except HttpClientError as error:
        return {"error": asdict(error.failure)}
    except (ValueError, UnicodeError) as error:
        return {"error": str(error)}


def run_experiment(
    base_url: str, output_dir: str | Path, *, repetitions: int = 3, interval: float = 0.2,
) -> dict:
    base = validate_target(base_url)
    parts = urlsplit(base)
    if parts.path != "/" or parts.query:
        raise ValueError("Informe somente a origem local do laboratório, sem caminho ou parâmetros.")
    if repetitions < 1:
        raise ValueError("O número de repetições deve ser positivo.")
    base = base.rstrip("/")
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    summary = {
        "experiment": "sqlite_positive_negative_control", "started_at": utc_now(),
        "scanner_version": __version__, "python_version": platform.python_version(),
        "repetitions_per_endpoint": repetitions,
        "positive_definition": "confirmed ou suspected; inconclusive é abstenção, nunca negativo",
        "dataset_before": health(base), "runs": [],
    }
    metrics = {"true_positive": 0, "true_negative": 0, "false_positive": 0, "false_negative": 0, "inconclusive": 0}
    if "error" not in summary["dataset_before"]:
        for repetition in range(1, repetitions + 1):
            for label, path, expected_positive in (
                ("vulnerable", VULNERABLE_PATH, True), ("safe", SAFE_PATH, False),
            ):
                report = run_sqli(base + path + "?q=apple", interval=interval)
                destination = write_json(report, output / f"{label}-{repetition:02d}.json")
                outcome = report.assessment.outcome
                if report.errors or outcome == "inconclusive":
                    cell = "inconclusive"
                else:
                    observed_positive = outcome in {"confirmed", "suspected"}
                    cell = ("true_" if observed_positive == expected_positive else "false_") + (
                        "positive" if observed_positive else "negative"
                    )
                metrics[cell] += 1
                summary["runs"].append({
                    "repetition": repetition, "endpoint": label, "target": report.target,
                    "expected_positive": expected_positive, "outcome": outcome, "metric": cell,
                    "findings": len(report.findings), "requests_attempted": report.to_dict()["summary"]["requests_attempted"],
                    "baseline_product_count": report.probes[0].product_count,
                    "baseline_product_ids_sha256": report.probes[0].product_ids_sha256,
                    "report": destination.name,
                })
    summary["dataset_after"] = health(base)
    summary["dataset_unchanged"] = (
        "error" not in summary["dataset_before"] and "error" not in summary["dataset_after"]
        and summary["dataset_before"] == summary["dataset_after"]
    )
    baselines = {run["baseline_product_ids_sha256"] for run in summary["runs"]}
    summary["same_baseline_products"] = bool(summary["runs"]) and len(baselines) == 1 and None not in baselines
    summary["metrics"] = metrics
    summary["status"] = "completed" if (
        len(summary["runs"]) == repetitions * 2 and not metrics["inconclusive"]
        and summary["dataset_unchanged"] and summary["same_baseline_products"]
    ) else "incomplete"
    summary["finished_at"] = utc_now()
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Executa controles SQLite positivo e negativo, preservando JSON por execução.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8001")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/sqlite-control"))
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args(argv)
    try:
        summary = run_experiment(args.base_url, args.output_dir, repetitions=args.repetitions)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Erro no experimento: {error}\n")
    for run in summary["runs"]:
        print(f"{run['endpoint']} #{run['repetition']}: {run['outcome']}, achados={run['findings']}, {run['report']}")
    print(f"Métricas observadas: {summary['metrics']}")
    print(f"Dados preservados: {summary['dataset_unchanged']}; referências equivalentes: {summary['same_baseline_products']}")
    print(f"Resumo: {args.output_dir / 'summary.json'}")
    return 0 if summary["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
