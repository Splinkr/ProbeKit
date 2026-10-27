"""XSS refletido independente: controles exclusivos, contextos e confirmação opcional."""

from dataclasses import replace
import secrets
from urllib.parse import parse_qsl, urlsplit

from scanner.http_client import HttpClient, HttpClientError
from scanner.models import (Confidence, Finding, FindingStatus, ParameterResult, RequestFailure,
                            ScanReport, XssProbeEvidence, utc_now)
from scanner.query import replace_parameter, select_parameters
from scanner.targets import validate_target
from scanner.xss_analysis import assess_xss, inspect_response

EXTRA_REQUESTS = 8


def prepare_parameters(url, samples=2, max_requests=10, parameter=None, all_parameters=False):
    selected = select_parameters(url, parameter, all_parameters)
    if samples < 2 or len(selected) * (samples + EXTRA_REQUESTS) > max_requests:
        raise ValueError(f"XSS requer duas referências e orçamento global mínimo de {len(selected) * (max(samples, 2) + EXTRA_REQUESTS)}.")
    return selected


def build_plan(url, parameter, samples=2, start_id=1):
    select_parameters(url, parameter)
    value = next(value for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True) if name == parameter)
    nonce = secrets.token_hex(12)
    prefix, callback = "WVX" + nonce, "wvxss_" + nonce
    markers = {role: prefix + suffix for role, suffix in (
        ("marker_1", "A"), ("marker_2", "B"), ("escape", "E"),
        ("attack_html", "H"), ("attack_attribute", "D"), ("attack_single", "S"), ("attack_double", "Q"))}

    def call(marker):
        return f'globalThis.{callback}("{marker}")'

    entries = [(f"baseline_{index + 1}", value, None) for index in range(samples)]
    entries += [(role, markers[role], markers[role]) for role in ("marker_1", "marker_2")]
    marker = markers["escape"]
    entries.append(("escape", marker + '<>&"\'' + marker + "END", marker))
    marker = markers["attack_html"]
    entries.append(("attack_html", marker + "</script><script>" + call(marker) + "</script>", marker))
    marker = markers["attack_attribute"]
    entries.append(("attack_attribute", marker + '\"\'><script>' + call(marker) + '</script><span data-wv="', marker))
    for role, quote in (("attack_single", "'"), ("attack_double", '"')):
        marker = markers[role]
        entries.append((role, marker + quote + ";" + call(marker) + ";//", marker))
    entries.append(("recovery", value, None))
    return [XssProbeEvidence(index, role, parameter, value, marker)
            for index, (role, value, marker) in enumerate(entries, start=start_id)], callback


def run_detection(client, report, plan, callback, *, browser=False):
    parameter = plan[0].parameter
    proof = {"status": "not_requested", "confirmed": False}
    current_responses = {}
    no_reflection = False
    try:
        for planned in plan:
            if no_reflection and (planned.role.startswith("attack_") or planned.role == "escape"):
                continue
            planned = replace(planned, request_id=client.request_count + 1)
            report.probes.append(planned)
            url = replace_parameter(report.target, parameter, planned.input_value)
            before = client.request_count
            try:
                response = client.get(url)
            except HttpClientError as error:
                report.errors.append(error.failure)
                break
            except KeyboardInterrupt:
                if client.request_count > before:
                    report.errors.append(RequestFailure(client.request_count, url, "interrupted", "Análise XSS interrompida."))
                raise
            report.responses.append(response)
            current_responses[planned.role] = response
            report.probes[-1] = inspect_response(planned, response, callback)
            if planned.role == "marker_2":
                markers = [probe for probe in report.probes if probe.parameter == parameter and probe.role in {"marker_1", "marker_2"}]
                no_reflection = len(markers) == 2 and all(not probe.reflections for probe in markers)
        preliminary = assess_xss(report, parameter, callback, proof, len(plan))
        if browser and preliminary.outcome == "suspected":
            from scanner.xss_browser import confirm_responses
            proof = confirm_responses(report, parameter, callback, timeout=client.timeout)
        elif browser:
            proof = {"status": "not_needed", "confirmed": False,
                     "reason": "Sem candidato HTML executável com controles completos."}
    finally:
        assessment = assess_xss(report, parameter, callback, proof, len(plan))
        report.parameter_results.append(ParameterResult(parameter, "reflected_xss", assessment,
            [probe.request_id for probe in report.probes if probe.parameter == parameter]))
        report.assessment = assessment
        if assessment.outcome in {"suspected", "confirmed"}:
            confirmed = assessment.outcome == "confirmed"
            report.findings.append(Finding(
                report.target, "xss", f"{'XSS refletido confirmado' if confirmed else 'Possível XSS refletido'} em {parameter}",
                Confidence.HIGH if confirmed else Confidence.LOW,
                FindingStatus.CONFIRMED if confirmed else FindingStatus.SUSPECTED,
                [response.request_id for response in current_responses.values()], assessment.rationale,
                "Execução de JavaScript no contexto da página. Nenhum dado privado foi acessado.",
                "Aplicar escape conforme o contexto; evitar interpolar entrada em HTML/JavaScript e usar CSP como defesa adicional.", parameter))


def run_xss(url, *, samples=2, timeout=5.0, max_requests=10, interval=0.2, max_body_bytes=1_048_576,
            parameter=None, all_parameters=False, browser=False):
    target = validate_target(url)
    selected = prepare_parameters(target, samples, max_requests, parameter, all_parameters)
    report = ScanReport(target, utc_now(), {
        "samples": samples, "max_requests": max_requests, "parameters": selected,
        "timeout_seconds": timeout, "interval_seconds": interval, "max_body_bytes": max_body_bytes,
        "planned_requests": len(selected) * (samples + EXTRA_REQUESTS), "scope": "loopback_only",
        "browser_requested": browser, "follow_redirects": False,
    }, mode="xss", schema_version="1.3")
    with HttpClient(timeout, max_requests, interval, max_body_bytes) as client:
        for name in selected:
            plan, callback = build_plan(target, name, samples, client.request_count + 1)
            run_detection(client, report, plan, callback, browser=browser)
    if len(report.parameter_results) > 1:
        from scanner.models import XssAssessment
        outcomes = [result.assessment.outcome for result in report.parameter_results]
        outcome = next(value for value in ("confirmed", "suspected", "inconclusive", "reflected_safe", "not_detected") if value in outcomes)
        report.assessment = XssAssessment(outcome, {}, "Resumo; consulte parameter_results para cada parâmetro.",
                                         [f"{result.parameter}: {result.assessment.outcome}" for result in report.parameter_results])
    report.finished_at = utc_now()
    return report
