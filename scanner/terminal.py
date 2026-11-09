"""Apresentação dos resultados já classificados, sem interferir nos detectores."""

from collections import Counter
import argparse
import builtins

from scanner.models import IntegratedScanReport


OUTCOMES = ("confirmed", "suspected", "inconclusive", "not_detected", "reflected_safe")


def safe_text(value) -> str:
    """Escapa controles externos sem normalizar Unicode ou alterar dados internos."""
    return "".join(f"\\x{ord(char):02x}" if ord(char) < 32 or 127 <= ord(char) <= 159
                   else char for char in str(value))


def safe_print(*values, trusted_layout=False, **options):
    builtins.print(*(str(value) if trusted_layout else safe_text(value) for value in values), **options)


class SafeArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **options):
        super().__init__(*args, **options)
        self.prog = safe_text(self.prog)

    def parse_args(self, args=None, namespace=None):
        import sys
        values = list(sys.argv[1:] if args is None else args)
        self.evidence_profile = 'shareable'
        for index, value in enumerate(values):
            if value.startswith('--evidence-profile='):
                self.evidence_profile = value.partition('=')[2]
            elif value == '--evidence-profile' and index + 1 < len(values):
                self.evidence_profile = values[index + 1]
        return super().parse_args(values, namespace)

    def error(self, message):
        if getattr(self, 'evidence_profile', 'shareable') != 'restricted':
            message = 'Argumentos inv?lidos; use --help para consultar op??es e limites.'
        super().error(safe_text(message))


def format_scan_results(report: IntegratedScanReport) -> str:
    """Conta avaliações individuais; não usa achados ou respostas como denominador."""
    data = report.to_dict()
    results = [*data["parameter_results"], *data["exposure_results"]]
    modules = list(dict.fromkeys([*data["settings"]["modules"], *(result["module"] for result in results)]))
    counts = Counter((result["module"], result["assessment"]["outcome"]) for result in results)
    widths = (10, *(len(outcome) for outcome in OUTCOMES))

    def row(values):
        return "  ".join(safe_text(value).ljust(width) for value, width in zip(values, widths)).rstrip()

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
