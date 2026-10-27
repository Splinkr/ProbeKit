"""Apresentação dos resultados já classificados, sem interferir nos detectores."""

from collections import Counter

from scanner.models import IntegratedScanReport


OUTCOMES = ("confirmed", "suspected", "inconclusive", "not_detected", "reflected_safe")


def format_scan_results(report: IntegratedScanReport) -> str:
    """Conta avaliações individuais; não usa achados ou respostas como denominador."""
    data = report.to_dict()
    results = [*data["parameter_results"], *data["exposure_results"]]
    modules = list(dict.fromkeys([*data["settings"]["modules"], *(result["module"] for result in results)]))
    counts = Counter((result["module"], result["assessment"]["outcome"]) for result in results)
    widths = (10, *(len(outcome) for outcome in OUTCOMES))

    def row(values):
        return "  ".join(str(value).ljust(width) for value, width in zip(values, widths)).rstrip()

    lines = ["", "Resumo do scan — ProbeKit", row(("Módulo", *OUTCOMES))]
    lines.append("-" * len(lines[-1]))
    for module in modules:
        lines.append(row((module, *(counts[module, outcome] for outcome in OUTCOMES))))
    lines.append(row(("TOTAL", *(sum(counts[module, outcome] for module in modules) for outcome in OUTCOMES))))
    unfinished = sum(target["status"] != "completed" for target in data["targets"])
    unclassified = sum(analysis.assessment is None for analysis in report.analyses)
    lines.extend([
        f"Avaliações classificadas: {len(results)} (por parâmetro/módulo ou arquivo).",
        f"Alvos planejados não concluídos: {unfinished}; análises sem classificação: {unclassified}.",
        "suspected indica suspeita; inconclusive indica falta de conclusão.",
        "not_detected e reflected_safe não garantem ausência de vulnerabilidades.",
    ])
    if not results:
        lines.append("Nenhuma avaliação classificada; consulte os limites e alvos ignorados no JSON.")
    return "\n".join(lines)
