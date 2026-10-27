"""SQLi para buscas de produtos do Juice Shop e do controle SQLite local."""

from dataclasses import replace
import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from scanner.analyzer import compare_responses
from scanner.http_client import HttpClient, HttpClientError
from scanner.models import (
    Confidence, Finding, FindingStatus, ProbeEvidence, ResponseEvidence,
    ScanReport, SqliAssessment,
)
from scanner.targets import validate_target

PAIRS = (17, 23)
EXTRA_REQUESTS = 8  # Aspa, escape, literal, dois pares booleanos e recuperação.
SIGNATURES = ("SQLITE_ERROR", "SQLITE_MISUSE", "SequelizeDatabaseError")
SUPPORTED_PATHS = {
    "/rest/products/search", "/control/vulnerable/search", "/control/safe/search",
}


def build_probe_plan(url: str, samples: int, max_requests: int) -> list[ProbeEvidence]:
    target = validate_target(url)
    parts = urlsplit(target)
    values = [value for key, value in parse_qsl(parts.query, keep_blank_values=True) if key == "q"]
    if parts.path not in SUPPORTED_PATHS or len(values) != 1:
        raise ValueError("SQLi requer um caminho de busca suportado (Juice Shop ou /control/{vulnerable,safe}/search) e um único q.")
    term = values[0]
    if not re.fullmatch(r"[\w -]{1,80}", term) or not term.strip():
        raise ValueError("Use em q um termo de referência simples, de 1 a 80 caracteres (ex.: apple).")
    if samples < 2:
        raise ValueError("SQLi requer pelo menos duas referências (--samples 2).")
    if samples + EXTRA_REQUESTS > max_requests:
        raise ValueError(f"SQLi requer --max-requests de pelo menos {samples + EXTRA_REQUESTS}.")
    entries = [(f"baseline_{index + 1}", term) for index in range(samples)]
    entries.extend([
        ("quote", term + "'"),
        ("escaped_quote", term + "''"),
        ("literal_control", term + " AND 17=17"),
    ])
    for number in PAIRS:
        for label, operand in (("true", number), ("false", number + 1)):
            # Encerra o LIKE, acrescenta a condição e reabre a string.
            # Preserva as duas alternativas de busca e o filtro deletedAt.
            value = f"{term}%' AND ({number}={operand}) AND '%' LIKE '%"
            entries.append((f"{label}_{number}", value))
    entries.append(("recovery", term))
    return [ProbeEvidence(index, role, "q", value)
            for index, (role, value) in enumerate(entries, start=1)]


def probe_url(target: str, value: str) -> str:
    parts = urlsplit(target)
    query = [(key, value if key == "q" else original)
             for key, original in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit(parts._replace(query=urlencode(query)))


def observe(probe: ProbeEvidence, response: ResponseEvidence) -> ProbeEvidence:
    signatures = [token for token in SIGNATURES if token.encode() in response.body]
    count = None
    fingerprint = None
    media_type = response.content_type.split(";", 1)[0].strip().lower()
    if response.status_code == 200 and media_type == "application/json":
        try:
            payload = json.loads(response.body)
            rows = payload.get("data") if isinstance(payload, dict) else None
            if (payload.get("status") == "success" and isinstance(rows, list)
                    and all(isinstance(row, dict) and type(row.get("id")) is int
                            and isinstance(row.get("name"), str) for row in rows)):
                ids = sorted(row["id"] for row in rows)
                if len(ids) == len(set(ids)):
                    count = len(ids)
                    fingerprint = hashlib.sha256(
                        json.dumps(ids, separators=(",", ":")).encode()
                    ).hexdigest()
        except (ValueError, UnicodeError, AttributeError):
            pass
    return replace(probe, response_received=True, product_count=count,
                   product_ids_sha256=fingerprint, sql_error_signatures=signatures)


def assess(report: ScanReport, samples: int) -> SqliAssessment:
    probes = {probe.role: probe for probe in report.probes}
    responses = {response.request_id: response for response in report.responses}
    baseline = probes.get("baseline_1")

    def valid(probe: ProbeEvidence | None) -> bool:
        return (probe is not None and probe.response_received
                and probe.product_count is not None and not probe.sql_error_signatures)

    def matches(probe: ProbeEvidence | None) -> bool:
        return bool(valid(baseline) and valid(probe)
                    and probe.product_ids_sha256 == baseline.product_ids_sha256)

    def empty(probe: ProbeEvidence | None) -> bool:
        return valid(probe) and probe.product_count == 0

    quote = probes.get("quote")
    quote_response = responses.get(quote.request_id) if quote else None
    controls = [probes.get("escaped_quote"), probes.get("literal_control"), probes.get("recovery")]
    checks = {
        "all_requests_completed": len(report.responses) == samples + EXTRA_REQUESTS and not report.errors,
        "baseline_nonempty": bool(valid(baseline) and baseline.product_count > 0),
        "baseline_stable": all(matches(probes.get(f"baseline_{index + 1}")) for index in range(samples)),
        "recovery_matches": matches(probes.get("recovery")),
        "escaped_quote_control_empty": empty(probes.get("escaped_quote")),
        "literal_control_empty": empty(probes.get("literal_control")),
        "new_sql_error": bool(quote and quote.sql_error_signatures and quote_response
                              and quote_response.status_code >= 400
                              and all(valid(control) for control in controls)
                              and valid(baseline)),
    }
    for number in PAIRS:
        checks[f"boolean_pair_{number}"] = bool(
            checks["baseline_nonempty"] and matches(probes.get(f"true_{number}"))
            and empty(probes.get(f"false_{number}"))
        )
    failed = [name for name, passed in checks.items() if not passed]
    if not failed:
        outcome = "confirmed"
        rationale = (
            "SQLi booleana confirmada neste endpoint: dois pares independentes preservaram "
            "os produtos da referência nas condições verdadeiras e retornaram zero nas falsas; "
            "referências e recuperação estáveis, controles válidos e erro SQL diferencial."
        )
    elif checks["new_sql_error"] or any(checks[f"boolean_pair_{n}"] for n in PAIRS):
        outcome = "suspected"
        rationale = "Há indício SQL específico, mas faltam controles para confirmar a SQLi."
    elif not all(checks[name] for name in (
        "all_requests_completed", "baseline_nonempty", "baseline_stable", "recovery_matches"
    )):
        outcome = "inconclusive"
        rationale = "Coleta incompleta ou referências inadequadas; não é possível concluir sobre SQLi."
    else:
        outcome = "not_detected"
        rationale = "Os testes executados não demonstraram SQLi; isso não comprova ausência de vulnerabilidade."
    return SqliAssessment(outcome, checks, rationale, [f"Critério não satisfeito: {name}" for name in failed])


def run_detection(client: HttpClient, report: ScanReport, plan: list[ProbeEvidence]) -> None:
    for planned in plan:
        report.probes.append(planned)
        try:
            response = client.get(probe_url(report.target, planned.input_value))
        except HttpClientError as error:
            report.errors.append(error.failure)
            break
        report.probes[-1] = observe(planned, response)
        if report.responses:
            report.comparisons.append(compare_responses(report.responses[0], response))
        report.responses.append(response)
    assessment = assess(report, report.settings["samples"])
    report.assessment = assessment
    if assessment.outcome in {"confirmed", "suspected"}:
        confirmed = assessment.outcome == "confirmed"
        report.findings.append(Finding(
            endpoint=report.target, category="sqli",
            title="SQL Injection booleana no parâmetro q" if confirmed else "Possível SQL Injection no parâmetro q",
            confidence=Confidence.HIGH if confirmed else Confidence.LOW,
            status=FindingStatus.CONFIRMED if confirmed else FindingStatus.SUSPECTED,
            evidence_request_ids=[response.request_id for response in report.responses],
            rationale=assessment.rationale,
            potential_impact=("Alteração da lógica da consulta de produtos. Acesso a usuários, "
                              "credenciais e escrita no banco não foram testados."),
            recommended_mitigation=("Substituir concatenação de q por consultas parametrizadas/bindings; "
                                    "não expor detalhes de erros SQL nas respostas HTTP."),
        ))
