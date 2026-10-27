"""Interface de linha de comando do ProbeKit."""

import argparse
from datetime import datetime, timezone
import math
from pathlib import Path
import sys

from scanner import __version__
from scanner.core import run_baseline, run_sqli
from scanner.discovery import discover
from scanner.pipeline import run_scan
from scanner.modules.xss import prepare_parameters as prepare_xss_parameters, run_xss
from scanner.modules import exposure
from scanner.exposure_profiles import PROFILES
from scanner.sqli_plans import CONTEXTS, prepare_parameters
from scanner.reporter import write_json, write_json_atomic
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


def nonnegative_int(value: str) -> int:
    result = int(value)
    if result < 0:
        raise argparse.ArgumentTypeError("Informe um inteiro não negativo.")
    return result


def discover_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="main.py discover", description="Inventaria links HTML e formulários GET na mesma origem local.")
    parser.add_argument("url", help="URL inicial local")
    parser.add_argument("--max-depth", type=nonnegative_int, default=2)
    parser.add_argument("--max-pages", type=positive_int, default=20)
    parser.add_argument("--max-requests", type=positive_int, default=20)
    parser.add_argument("--timeout", type=positive_float, default=5.0)
    parser.add_argument("--interval", type=interval_float, default=0.2)
    parser.add_argument("--max-body-bytes", type=positive_int, default=1_048_576)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = discover(
            args.url, max_depth=args.max_depth, max_pages=args.max_pages, max_requests=args.max_requests,
            timeout=args.timeout, interval=args.interval, max_body_bytes=args.max_body_bytes,
        )
    except ValueError as error:
        parser.error(str(error))
    destination = args.output or Path("reports") / (
        "discover-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json"
    )
    try:
        output = write_json(report, destination)
    except OSError as error:
        print(f"Erro ao gravar inventário: {error}", file=sys.stderr)
        return 1
    for endpoint in report.endpoints:
        sources = ", ".join(dict.fromkeys(source.kind for source in endpoint.sources))
        parameters = ", ".join(dict.fromkeys(parameter.name for parameter in endpoint.parameters)) or "nenhum"
        print(f"{endpoint.method} {endpoint.endpoint} | parâmetros: {parameters} | origem: {sources}")
    print(f"Páginas: {len(report.pages)}; requisições: {report.requests_attempted}; erros: {len(report.errors)}")
    if report.stop_reasons:
        print(f"Limites atingidos: {', '.join(report.stop_reasons)}")
    print(f"Inventário JSON: {output}")
    return 1 if report.errors else 0


def scan_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="main.py scan", description="Descobre parâmetros GET e executa SQLi, XSS e exposure na mesma origem loopback.")
    parser.add_argument("url", help="URL inicial local autorizada")
    parser.add_argument("--max-depth", type=nonnegative_int, default=2)
    parser.add_argument("--max-pages", type=positive_int, default=20)
    parser.add_argument("--max-requests", type=positive_int, default=100, help="Orçamento global: descoberta + módulos selecionados")
    parser.add_argument("--timeout", type=positive_float, default=5.0)
    parser.add_argument("--interval", type=interval_float, default=0.2)
    parser.add_argument("--max-body-bytes", type=positive_int, default=1_048_576)
    parser.add_argument("--samples", type=positive_int, default=2)
    parser.add_argument("--sqli-context", choices=CONTEXTS, default="like")
    parser.add_argument("--modules", "--module", nargs="+", choices=("sqli", "xss", "exposure"), default=["sqli"])
    parser.add_argument("--exposure-profiles", nargs="+", choices=tuple(PROFILES))
    parser.add_argument("--exposure-base-path", help="Diretório-base exposure na mesma origem (padrão: /)")
    parser.add_argument("--xss-browser", action="store_true", help="Confirmar XSS por replay em navegador local isolado")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    destination = args.output or Path("reports") / (
        "scan-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json"
    )
    try:
        report = run_scan(
            args.url, max_depth=args.max_depth, max_pages=args.max_pages, max_requests=args.max_requests,
            timeout=args.timeout, interval=args.interval, max_body_bytes=args.max_body_bytes,
            samples=args.samples, context=args.sqli_context,
            modules=tuple(args.modules), xss_browser=args.xss_browser,
            exposure_profiles=tuple(args.exposure_profiles) if args.exposure_profiles is not None else None,
            exposure_base_path=args.exposure_base_path,
            checkpoint=lambda current: write_json_atomic(current, destination),
        )
    except ValueError as error:
        parser.error(str(error))
    except OSError as error:
        print(f"Erro ao gravar relatório consolidado: {error}", file=sys.stderr)
        return 1
    for analysis in report.analyses:
        result = analysis.assessment
        label = f"{'arquivo' if analysis.mode == 'exposure' else result.parameter}: {result.outcome}" if result else "interrompida antes da classificação"
        print(f"{analysis.target} | {analysis.mode}: {label}")
    summary = report.to_dict()["summary"]
    print(f"Estado: {report.status}; endpoints: {summary['endpoints_discovered']}; parâmetros analisados: {summary['parameters_analyzed']}")
    if "exposure" in args.modules:
        print(f"Arquivos analisados: {summary['files_analyzed']}")
    analysis_label = "SQLi" if args.modules == ["sqli"] else "análise"
    print(f"Requisições: {summary['requests_used']}/{args.max_requests} (descoberta={summary['discovery_requests']}, {analysis_label}={summary['analysis_requests']})")
    print(f"Alvos ignorados: {summary['targets_ignored']}; limites: {', '.join(report.stop_reasons) or 'nenhum'}")
    print(f"Relatório consolidado JSON: {destination}")
    return 130 if report.status == "interrupted" else 1 if report.status == "incomplete" else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Referências HTTP locais, SQLi/XSS por parâmetro GET e exposição de arquivos com controles.",
        epilog="Descoberta HTML: main.py discover URL --help. Fluxo completo: main.py scan URL --help",
    )
    parser.add_argument("url", help="URL http(s) em localhost ou IP loopback")
    parser.add_argument("--module", choices=("baseline", "sqli", "xss", "exposure"), default="baseline", help="Modo de execução (padrão: baseline)")
    parser.add_argument("--exposure-profiles", nargs="+", choices=tuple(PROFILES))
    parser.add_argument("--xss-browser", action="store_true", help="Confirmar XSS por replay em navegador local isolado")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--parameter", help="Parâmetro GET único a testar")
    selection.add_argument("--all-parameters", action="store_true", help="Testar cada parâmetro GET individualmente")
    parser.add_argument("--sqli-context", choices=CONTEXTS, default="like", help="Contexto de aspas simples: LIKE ou igualdade (padrão: like)")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--samples", type=positive_int, default=2, help="Número de referências (padrão: 2)")
    parser.add_argument("--timeout", type=positive_float, default=5.0, help="Timeout de conexão/leitura, em segundos (padrão: 5)")
    parser.add_argument("--max-requests", type=positive_int, default=10, help="Orçamento máximo de requisições (padrão: 10)")
    parser.add_argument("--interval", type=interval_float, default=0.2, help="Intervalo mínimo entre inícios de requisições (padrão: 0.2)")
    parser.add_argument("--max-body-bytes", type=positive_int, default=1_048_576, help="Limite de bytes descomprimidos por resposta")
    parser.add_argument("--output", type=Path, help="Destino JSON (padrão: reports/<modo>-<UTC>.json)")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "discover":
        return discover_main(arguments[1:])
    if arguments and arguments[0] == "scan":
        return scan_main(arguments[1:])
    parser = build_parser()
    args = parser.parse_args(arguments)
    try:
        target = validate_target(args.url)
        if args.samples > args.max_requests:
            raise ValueError("--samples não pode exceder --max-requests.")
        if args.module == "sqli":
            prepare_parameters(target, args.samples, args.max_requests, args.parameter, args.all_parameters, args.sqli_context)
        elif args.module == "xss":
            prepare_xss_parameters(target, args.samples, args.max_requests, args.parameter, args.all_parameters)
        elif args.module == "exposure":
            if args.parameter is not None or args.all_parameters or args.sqli_context != "like":
                raise ValueError("Exposure analisa arquivos, não parâmetros/contextos SQL.")
            exposure.prepare(target, args.exposure_profiles if args.exposure_profiles is not None else exposure.DEFAULT_PROFILES,
                             args.samples, args.max_requests)
        elif args.parameter is not None or args.all_parameters or args.sqli_context != "like":
            raise ValueError("Seleção de parâmetros requer --module sqli ou xss.")
        if args.xss_browser and args.module != "xss":
            raise ValueError("--xss-browser requer --module xss.")
        if args.module == "xss" and args.sqli_context != "like":
            raise ValueError("--sqli-context não se aplica ao módulo XSS.")
        if args.exposure_profiles is not None and args.module != "exposure":
            raise ValueError("--exposure-profiles requer --module exposure.")
    except (TargetError, ValueError) as error:
        parser.error(str(error))
    runner = run_sqli if args.module == "sqli" else run_xss if args.module == "xss" else exposure.run_exposure if args.module == "exposure" else run_baseline
    extra = {"parameter": args.parameter, "all_parameters": args.all_parameters, "context": args.sqli_context} if args.module == "sqli" else {
        "parameter": args.parameter, "all_parameters": args.all_parameters, "browser": args.xss_browser} if args.module == "xss" else {
        "profiles": args.exposure_profiles if args.exposure_profiles is not None else exposure.DEFAULT_PROFILES} if args.module == "exposure" else {}
    report = runner(
        target, samples=args.samples, timeout=args.timeout,
        max_requests=args.max_requests, interval=args.interval,
        max_body_bytes=args.max_body_bytes,
        **extra,
    )
    destination = args.output or Path("reports") / (
        args.module + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json"
    )
    try:
        output = write_json(report, destination)
    except OSError as error:
        print(f"Erro ao gravar relatório: {error}", file=sys.stderr)
        return 1
    print(f"Alvo: {report.target}")
    print(f"Conectividade HTTP: {'OK' if report.reachable else 'FALHOU'}")
    probes = {probe.request_id: probe for probe in report.probes}
    for response in report.responses:
        probe = probes.get(response.request_id)
        features = getattr(probe, "features", None)
        label = (f"{probe.parameter}/{probe.role} (formato={features.format if features else getattr(probe, 'content_format', 'indefinido')})"
                 if probe else "Referência")
        print(f"  {label} #{response.request_id}: HTTP {response.status_code}, {response.size_bytes} bytes, {response.elapsed_ms:.1f} ms")
        if probe and getattr(probe, "sql_error_signatures", []):
            print(f"    Sinais SQL: {', '.join(probe.sql_error_signatures)}")
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
    if report.assessment:
        print(f"{'Exposure' if args.module == 'exposure' else 'XSS' if args.module == 'xss' else 'SQLi'}: {report.assessment.outcome}")
        print(report.assessment.rationale)
        for result in report.parameter_results:
            print(f"  Parâmetro {result.parameter}: {result.assessment.outcome} ({result.context})")
        for result in getattr(report, "exposure_results", []):
            print(f"  Arquivo {result.url}: {result.assessment.outcome}")
        for finding in report.findings:
            print(f"  Achado: {finding.status.value}, confiança {finding.confidence.value}; evidências {finding.evidence_request_ids}")
        for limitation in report.assessment.limitations:
            print(f"  {limitation}")
    else:
        print("Modo referência: diferenças não confirmam vulnerabilidades; nenhum detector foi executado.")
    print(f"Relatório JSON: {output}")
    return 1 if report.errors or (report.assessment and report.assessment.outcome == "inconclusive") or any(
        result.assessment.outcome == "inconclusive" for result in report.parameter_results
    ) or any(
        result.assessment.outcome == "inconclusive" for result in getattr(report, "exposure_results", [])
    ) else 0


if __name__ == "__main__":
    raise SystemExit(main())
