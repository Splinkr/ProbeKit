"""Orquestra referências HTTP e a análise SQLi controlada de buscas locais."""

from scanner.analyzer import compare_responses
from scanner.http_client import HttpClient, HttpClientError
from scanner.models import ScanReport, utc_now
from scanner.modules.sqli import build_probe_plan, run_detection
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
) -> ScanReport:
    target = validate_target(url)
    plan = build_probe_plan(target, samples, max_requests)
    report = ScanReport(target=target, started_at=utc_now(), mode="sqli", schema_version="1.1", settings={
        "samples": samples, "timeout_seconds": timeout, "max_requests": max_requests,
        "interval_seconds": interval, "max_body_bytes": max_body_bytes,
        "follow_redirects": False, "scope": "loopback_only", "parameter": "q",
        "planned_requests": len(plan), "confirmation_scope": "boolean_condition_in_product_search",
    })
    with HttpClient(timeout, max_requests, interval, max_body_bytes) as client:
        run_detection(client, report, plan)
    report.finished_at = utc_now()
    return report
