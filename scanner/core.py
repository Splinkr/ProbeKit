"""Orquestra referências HTTP e a análise SQLi por parâmetro em endpoints locais."""

from scanner.analyzer import compare_responses
from scanner.http_client import HttpClient, HttpClientError
from scanner.models import ScanReport, SqliAssessment, utc_now
from scanner.modules.sqli import build_probe_plan, run_detection
from scanner.sqli_plans import EXTRA_REQUESTS, available_parameters, prepare_parameters
from scanner.targets import validate_target


def run_baseline(
    url: str,
    *,
    samples: int = 2,
    timeout: float = 5.0,
    max_requests: int = 10,
    interval: float = 0.2,
    max_body_bytes: int = 1_048_576,
) -> ScanReport:
    target = validate_target(url)
    if samples < 1 or samples > max_requests:
        raise ValueError("A quantidade de referências deve estar entre 1 e max-requests.")
    report = ScanReport(target=target, started_at=utc_now(), settings={
        "samples": samples,
        "timeout_seconds": timeout,
        "max_requests": max_requests,
        "interval_seconds": interval,
        "max_body_bytes": max_body_bytes,
        "follow_redirects": False,
        "scope": "loopback_only",
    })
    with HttpClient(timeout, max_requests, interval, max_body_bytes) as client:
        for _ in range(samples):
            try:
                response = client.get(target)
            except HttpClientError as error:
                report.errors.append(error.failure)
                # Interrompe na primeira falha; não repete um alvo indisponível.
                break
            if report.responses:
                report.comparisons.append(compare_responses(report.responses[0], response))
            report.responses.append(response)
    report.finished_at = utc_now()
    return report


def run_sqli(
    url: str, *, samples: int = 2, timeout: float = 5.0,
    max_requests: int = 10, interval: float = 0.2, max_body_bytes: int = 1_048_576,
    parameter: str | None = None, all_parameters: bool = False, context: str = "like",
) -> ScanReport:
    target = validate_target(url)
    selected = prepare_parameters(target, samples, max_requests, parameter, all_parameters, context)
    report = ScanReport(target=target, started_at=utc_now(), mode="sqli", schema_version="1.2", settings={
        "samples": samples, "timeout_seconds": timeout, "max_requests": max_requests,
        "interval_seconds": interval, "max_body_bytes": max_body_bytes,
        "follow_redirects": False, "scope": "loopback_only", "parameter": selected[0] if len(selected) == 1 else None,
        "parameters": selected, "context": context,
        "available_parameters": available_parameters(target),
        "planned_requests": len(selected) * (samples + EXTRA_REQUESTS), "confirmation_scope": "controlled_boolean_read_condition",
    })
    with HttpClient(timeout, max_requests, interval, max_body_bytes) as client:
        for name in selected:
            plan = build_probe_plan(target, samples, max_requests, parameter=name, context=context, start_id=client.request_count + 1)
            run_detection(client, report, plan)
    if len(report.parameter_results) > 1:
        outcomes = [result.assessment.outcome for result in report.parameter_results]
        outcome = next(value for value in ("confirmed", "suspected", "inconclusive", "not_detected") if value in outcomes)
        report.assessment = SqliAssessment(
            outcome, {"all_requests_completed": all(result.assessment.checks["all_requests_completed"] for result in report.parameter_results),
                      "all_parameters_conclusive": all(result.assessment.outcome != "inconclusive" for result in report.parameter_results)},
            "Resumo de parâmetros independentes; consulte parameter_results para critérios, limites e conclusão individual.",
            [f"{result.parameter}: {result.assessment.outcome}" for result in report.parameter_results], context=context,
        )
    report.finished_at = utc_now()
    return report
