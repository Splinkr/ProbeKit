"""Interface de linha de comando do WebVuln Scanner."""

import argparse
from datetime import datetime, timezone
import math
from pathlib import Path
import sys

from scanner import __version__
from scanner.core import run_baseline
from scanner.reporter import write_json
from scanner.targets import TargetError, validate_target


def positive_int(value: str) -> int:
    result = int(value)
    if result < 1:
        raise argparse.ArgumentTypeError("Informe um inteiro positivo.")
    return result


def positive_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError("Informe um número positivo e finito.")
    return result


def interval_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise argparse.ArgumentTypeError("Informe um número não negativo e finito.")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Coleta referências HTTP locais e compara respostas. Não executa detecção de vulnerabilidades."
    )
    parser.add_argument("url", help="URL http(s) em localhost ou IP loopback")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--samples", type=positive_int, default=2, help="Número de referências (padrão: 2)")
    parser.add_argument("--timeout", type=positive_float, default=5.0, help="Timeout de conexão/leitura, em segundos (padrão: 5)")
    parser.add_argument("--max-requests", type=positive_int, default=10, help="Orçamento máximo de requisições (padrão: 10)")
    parser.add_argument("--interval", type=interval_float, default=0.2, help="Intervalo mínimo entre inícios de requisições (padrão: 0.2)")
    parser.add_argument("--max-body-bytes", type=positive_int, default=1_048_576, help="Limite de bytes descomprimidos por resposta")
    parser.add_argument("--output", type=Path, help="Destino JSON (padrão: reports/baseline-<UTC>.json)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        target = validate_target(args.url)
        if args.samples > args.max_requests:
            raise ValueError("--samples não pode exceder --max-requests.")
    except (TargetError, ValueError) as error:
        parser.error(str(error))
    report = run_baseline(
        target, samples=args.samples, timeout=args.timeout,
        max_requests=args.max_requests, interval=args.interval,
        max_body_bytes=args.max_body_bytes,
    )
    destination = args.output or Path("reports") / (
        "baseline-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json"
    )
    try:
        output = write_json(report, destination)
    except OSError as error:
        print(f"Erro ao gravar relatório: {error}", file=sys.stderr)
        return 1
    print(f"Alvo: {report.target}")
    print(f"Conectividade HTTP: {'OK' if report.reachable else 'FALHOU'}")
    for response in report.responses:
        print(f"  Referência #{response.request_id}: HTTP {response.status_code}, {response.size_bytes} bytes, {response.elapsed_ms:.1f} ms")
    for comparison in report.comparisons:
        print(
            f"  Comparação #{comparison.compared_request_id}: "
            f"status alterado={comparison.status_changed}, "
            f"corpo alterado={comparison.body_changed}, "
            f"diferença={comparison.size_delta_bytes:+d} bytes, "
            f"similaridade da amostra={comparison.sample_similarity:.1%}"
        )
    for error in report.errors:
        print(f"  Erro [{error.kind}]: {error.message}", file=sys.stderr)
    print("Modo referência: diferenças não confirmam vulnerabilidades; detectores ainda não implementados.")
    print(f"Relatório JSON: {output}")
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
