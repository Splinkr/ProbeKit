"""Execução SQLi e fachada compatível; planos, características e decisões são separados."""

from scanner.analyzer import compare_responses
from scanner.http_client import HttpClient, HttpClientError
from scanner.models import Confidence, Finding, FindingStatus, ParameterResult, RequestFailure, ScanReport
from scanner.sqli_classification import assess
from scanner.sqli_features import SIGNATURES, observe
from scanner.sqli_plans import EXTRA_REQUESTS, PAIRS, build_probe_plan, probe_url, select_parameters


def run_detection(client: HttpClient, report: ScanReport, plan) -> None:
    try:
        _execute_plan(client, report, plan)
    finally:
        _finish_detection(report, plan[0].parameter, plan[0].context)


def _execute_plan(client: HttpClient, report: ScanReport, plan) -> None:
    parameter = plan[0].parameter
    first_response = None
    for planned in plan:
        report.probes.append(planned)
        before = client.request_count
        request_url = probe_url(report.target, planned.input_value, parameter)
        try:
            response = client.get(request_url)
        except HttpClientError as error:
            report.errors.append(error.failure)
            break
        except KeyboardInterrupt:
            if client.request_count > before:
                report.errors.append(RequestFailure(client.request_count, request_url, "interrupted", "Análise interrompida pelo usuário."))
            raise
        report.probes[-1] = observe(planned, response)
        if first_response is not None:
            report.comparisons.append(compare_responses(first_response, response))
        else:
            first_response = response
        report.responses.append(response)


def _finish_detection(report: ScanReport, parameter: str, context: str) -> None:
    assessment = assess(report, report.settings['samples'], parameter=parameter, context=context)
    evidence_ids = [probe.request_id for probe in report.probes if probe.parameter == parameter]
    report.parameter_results.append(ParameterResult(parameter, context, assessment, evidence_ids))
    report.assessment = assessment
    if assessment.outcome in {'confirmed', 'suspected'}:
        confirmed = assessment.outcome == 'confirmed'
        report.findings.append(Finding(
            endpoint=report.target, parameter=parameter, category='sqli',
            title=f'SQL Injection booleana no parâmetro {parameter}' if confirmed else f'Possível SQL Injection no parâmetro {parameter}',
            confidence=Confidence.HIGH if confirmed else Confidence.LOW,
            status=FindingStatus.CONFIRMED if confirmed else FindingStatus.SUSPECTED,
            evidence_request_ids=[response.request_id for response in report.responses if response.request_id in evidence_ids],
            rationale=assessment.rationale,
            potential_impact='Alteração da lógica de uma consulta de leitura. Usuários, credenciais e escrita no banco não foram testados.',
            recommended_mitigation='Usar consultas parametrizadas/bindings e não expor detalhes internos de erros SQL.',
        ))
