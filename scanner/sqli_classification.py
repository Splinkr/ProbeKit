"""Classificação diferencial conservadora, independente do transporte e da rota."""

from scanner.models import ProbeEvidence, ScanReport, SqliAssessment
from scanner.sqli_plans import EXTRA_REQUESTS, PAIRS


def assess(report: ScanReport, samples: int, *, parameter: str | None = None, context: str = "like") -> SqliAssessment:
    selected = [probe for probe in report.probes if parameter is None or probe.parameter == parameter]
    probes = {probe.role: probe for probe in selected}
    responses = {response.request_id: response for response in report.responses}
    baseline = probes.get("baseline_1")

    def valid(probe: ProbeEvidence | None) -> bool:
        if probe is None or not probe.response_received or probe.sql_error_signatures:
            return False
        return probe.features.valid if probe.features is not None else probe.product_count is not None

    def identity(probe):
        if probe.features is not None:
            return probe.features.format, probe.features.fingerprint
        return "json", probe.product_ids_sha256

    def count(probe):
        return probe.features.result_count if probe.features is not None else probe.product_count

    def matches(first, second):
        return bool(valid(first) and valid(second) and identity(first) == identity(second))

    def nonempty(probe):
        return bool(valid(probe) and (count(probe) > 0 if count(probe) is not None else probe.features.nonempty))

    false_first, false_second = (probes.get(f"false_{number}") for number in PAIRS)
    false_stable = matches(false_first, false_second)

    def empty(probe):
        if not valid(probe):
            return False
        if count(probe) is not None:
            return count(probe) == 0
        return bool(false_stable and matches(probe, false_first) and not matches(probe, baseline))

    quote = probes.get("quote")
    quote_response = responses.get(quote.request_id) if quote else None
    controls = [probes.get(role) for role in ("escaped_quote", "literal_control", "recovery")]
    selected_ids = {probe.request_id for probe in selected}
    checks = {
        "all_requests_completed": len(selected) == samples + EXTRA_REQUESTS
            and all(probe.response_received and probe.request_id in responses for probe in selected)
            and not any(error.request_id in selected_ids for error in report.errors),
        "baseline_nonempty": nonempty(baseline),
        "baseline_stable": all(matches(baseline, probes.get(f"baseline_{index + 1}")) for index in range(samples)),
        "recovery_matches": matches(baseline, probes.get("recovery")),
        "escaped_quote_control_empty": empty(probes.get("escaped_quote")),
        "literal_control_empty": empty(probes.get("literal_control")),
        "new_sql_error": bool(quote and quote.sql_error_signatures and quote_response
            and quote_response.status_code >= 400 and valid(baseline) and all(valid(control) for control in controls)),
        "false_responses_stable": false_stable,
    }
    for number in PAIRS:
        checks[f"boolean_pair_{number}"] = bool(
            checks["baseline_nonempty"] and matches(baseline, probes.get(f"true_{number}"))
            and empty(probes.get(f"false_{number}"))
        )
    failed = [name for name, passed in checks.items() if not passed]
    if not failed:
        outcome = "confirmed"
        rationale = ("SQLi booleana confirmada no parâmetro testado: dois pares preservam a referência nas "
                     "condições verdadeiras e coincidem com controles negativos nas falsas; referências e "
                     "recuperação estáveis, respostas negativas repetíveis e erro SQL diferencial.")
    elif checks["new_sql_error"] or any(checks[f"boolean_pair_{number}"] for number in PAIRS):
        outcome = "suspected"
        rationale = "Há indício SQL específico ou par booleano coerente, mas faltam controles para confirmar."
    elif not all(checks[name] for name in ("all_requests_completed", "baseline_nonempty", "baseline_stable", "recovery_matches")):
        outcome = "inconclusive"
        rationale = "Coleta incompleta ou referências inadequadas; não é possível concluir sobre SQLi."
    elif not all(valid(probes.get(role)) for role in ("escaped_quote", "literal_control", "true_17", "false_17", "true_23", "false_23")):
        outcome = "inconclusive"
        rationale = "Sondas rejeitadas, páginas de erro ou formato incompatível impediram a comparação controlada."
    else:
        outcome = "not_detected"
        rationale = "O plano executado não demonstrou SQLi; isso não comprova ausência de vulnerabilidade."
    limitations = [f"Critério não satisfeito: {name}" for name in failed]
    formats = {probe.features.format for probe in selected if probe.features}
    if formats & {"html", "text"}:
        limitations.append("HTML/texto usam conteúdo visível normalizado; variações visíveis não são removidas. Não há interpretação universal de resultados.")
    limitations.append(f"Perfil {context}: somente contexto textual entre aspas simples; não testa SQLi numérica, temporal, UNION ou escrita.")
    return SqliAssessment(outcome, checks, rationale, limitations, parameter, context)
