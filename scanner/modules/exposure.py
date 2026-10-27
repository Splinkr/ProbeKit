"""Verificação limitada de arquivos por estrutura, repetição e controles inexistentes."""

from scanner.exposure_analysis import assess, observe
from scanner.exposure_models import ExposureAssessment, ExposureReport, ExposureResult
from scanner.exposure_profiles import DEFAULT_PROFILES, base_url, build_plan, file_url, request_cost, select_profiles
from scanner.http_client import HttpClient, HttpClientError
from scanner.models import Confidence, Finding, FindingStatus, RequestFailure, utc_now


def prepare(url, profiles=DEFAULT_PROFILES, samples=2, max_requests=10):
    base = base_url(url)
    specs = select_profiles(profiles)
    required = len(specs) * request_cost(samples)
    if required > max_requests:
        raise ValueError(f"Exposure requer --max-requests de pelo menos {required} para os perfis selecionados.")
    return base, specs


def new_report(target, samples=2, **settings):
    return ExposureReport(target, utc_now(), {"samples": samples, "scope": "same_origin_loopback",
        "follow_redirects": False, "store_content": False, "store_key_names": False, "store_values": False, **settings})


def run_file(client, report, base, spec, samples=2):
    observations, failures = [], []
    url = file_url(base, spec)
    try:
        for role, request_url in build_plan(base, spec, samples):
            before = client.request_count
            try:
                raw = client.get(request_url)
            except HttpClientError as error:
                report.errors.append(error.failure)
                failures.append(error.failure)
                break
            except KeyboardInterrupt:
                if client.request_count > before:
                    failure = RequestFailure(client.request_count, request_url, "interrupted", "Verificação exposure interrompida.")
                    report.errors.append(failure)
                    failures.append(failure)
                raise
            # O relatório recebe um objeto que nem sequer possui corpo/cabeçalhos arbitrários.
            observation = observe(raw, role)
            observations.append(observation)
            report.responses.append(observation)
            del raw
    finally:
        assessment = assess(observations, failures, spec.kind, samples)
        ids = [item.request_id for item in observations] + [error.request_id for error in failures]
        report.exposure_results.append(ExposureResult(url, spec.profile, spec.kind, assessment, sorted(ids)))
        report.assessment = assessment
        if assessment.outcome in {"confirmed", "suspected"}:
            confirmed = assessment.outcome == "confirmed"
            report.findings.append(Finding(url, "exposure", "Arquivo potencialmente sensível acessível" if confirmed else "Possível exposição de arquivo",
                Confidence.HIGH if confirmed else Confidence.LOW,
                FindingStatus.CONFIRMED if confirmed else FindingStatus.SUSPECTED,
                [item.request_id for item in observations], assessment.rationale,
                "Acesso público a configuração, backup ou metadados de repositório; validade de segredos não avaliada.",
                "Remover artefatos privados da raiz pública, bloquear acesso e revisar o processo de publicação."))


def run_exposure(url, *, profiles=DEFAULT_PROFILES, samples=2, timeout=5.0, max_requests=10,
                 interval=0.2, max_body_bytes=1_048_576):
    base, specs = prepare(url, profiles, samples, max_requests)
    report = new_report(base, samples, profiles=list(dict.fromkeys(profiles)), max_requests=max_requests,
        timeout_seconds=timeout, interval_seconds=interval, max_body_bytes=max_body_bytes,
        planned_requests=len(specs) * request_cost(samples))
    with HttpClient(timeout, max_requests, interval, max_body_bytes) as client:
        for spec in specs:
            run_file(client, report, base, spec, samples)
    if len(report.exposure_results) > 1:
        outcomes = [result.assessment.outcome for result in report.exposure_results]
        outcome = next(value for value in ("confirmed", "suspected", "inconclusive", "not_detected") if value in outcomes)
        report.assessment = ExposureAssessment(outcome, {}, "Resumo; consulte exposure_results para cada arquivo.",
            [f"{result.url}: {result.assessment.outcome}" for result in report.exposure_results])
    report.finished_at = utc_now()
    return report
