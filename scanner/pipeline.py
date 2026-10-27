"""Descoberta e SQLi na mesma origem, sessão, sequência de IDs e orçamento."""

from collections.abc import Callable
from urllib.parse import urlsplit

from scanner.discovery import crawl, new_discovery_report, normalize_url, origin
from scanner.http_client import HttpClient, HttpClientError
from scanner.models import IntegratedScanReport, ScanReport, utc_now
from scanner.modules.sqli import run_detection
from scanner.sqli_plans import CONTEXTS, EXTRA_REQUESTS, available_parameters, build_probe_plan
from scanner.targets import TargetError, validate_target


class ScopedHttpClient(HttpClient):
    def __init__(self, target, requests, **options):
        super().__init__(**options)
        self.scope = origin(target)
        self.requests = requests
        self.phase = "discovery"

    def get(self, url):
        target = validate_target(url)
        if origin(target) != self.scope:
            raise TargetError("Destino fora da origem autorizada para scan.")
        before = self.request_count
        entry = {"phase": self.phase, "url": target, "method": "GET"}
        try:
            response = super().get(target)
        except HttpClientError as error:
            entry.update(status="failed", error=error.failure.kind)
            raise
        except KeyboardInterrupt:
            entry.update(status="interrupted")
            raise
        else:
            entry.update(status="received", status_code=response.status_code)
            return response
        finally:
            if self.request_count > before:
                self.requests.append({"request_id": self.request_count, **entry})


def collect_targets(report: IntegratedScanReport) -> None:
    """Deduplica URL canônica/parâmetro; nunca inventa valores de formulários."""
    known = {}
    discovery = report.discovery
    responses = {normalize_url(page["url"]): page for page in discovery.pages}
    failures = {normalize_url(error.url) for error in discovery.errors}
    context = report.settings["sqli_context"]

    def ignore(candidate, reason, parameter=None, detail=None):
        report.ignored_targets.append({"url": candidate["url"], "parameter": parameter,
                                       "source": candidate["source"], "reason": reason, "detail": detail})

    for candidate in discovery.candidates:
        url, source = candidate["url"], candidate["source"]
        try:
            url = normalize_url(url)
            if origin(url) != origin(report.target):
                raise TargetError("Fora da origem autorizada.")
        except ValueError as error:
            ignore(candidate, "outside_authorized_origin", detail=str(error))
            continue
        if source["depth"] > report.settings["max_depth"]:
            ignore(candidate, "max_depth")
            continue
        if source["kind"] == "get_form":
            names = list(dict.fromkeys(candidate["form_parameters"] + available_parameters(url)))
            for name in names or [None]:
                ignore(candidate, "form_reference_values_unavailable", name)
            continue
        if url in failures:
            ignore(candidate, "discovery_transport_failure")
            continue
        response = responses.get(url)
        if response and not 200 <= response["status_code"] < 300:
            ignore(candidate, "redirect_not_followed" if 300 <= response["status_code"] < 400 else "discovery_http_error")
            continue
        names = available_parameters(url)
        if not names:
            ignore(candidate, "no_query_parameters")
            continue
        for name in names:
            key = (url, name, context)
            if key in known:
                if source not in known[key]["sources"]:
                    known[key]["sources"].append(source)
                ignore(candidate, "duplicate_target", name)
                continue
            try:
                build_probe_plan(url, report.settings["samples"], report.settings["samples"] + EXTRA_REQUESTS,
                                 parameter=name, context=context)
            except ValueError as error:
                ignore(candidate, "unsupported_parameter_reference", name, str(error))
                continue
            target = {"url": url, "endpoint": urlsplit(url)._replace(query="").geturl(),
                      "parameter": name, "context": context, "sources": [source], "status": "pending"}
            known[key] = target
            report.targets.append(target)


def run_scan(
    url: str, *, max_depth: int = 2, max_pages: int = 20, max_requests: int = 100,
    timeout: float = 5.0, interval: float = 0.2, max_body_bytes: int = 1_048_576,
    samples: int = 2, context: str = "like",
    checkpoint: Callable[[IntegratedScanReport], None] | None = None,
) -> IntegratedScanReport:
    discovery = new_discovery_report(url, max_depth=max_depth, max_pages=max_pages, max_requests=max_requests,
                                      timeout=timeout, interval=interval, max_body_bytes=max_body_bytes)
    if samples < 2 or context not in CONTEXTS:
        raise ValueError("scan requer samples >= 2 e contexto like ou quoted.")
    report = IntegratedScanReport(discovery.target, utc_now(), {
        **discovery.settings, "samples": samples, "sqli_context": context,
        "submit_forms": False, "global_request_budget": True,
    }, discovery, limitations=[
        "Descoberta estática HTML; não executa JavaScript nem presume encontrar APIs internas.",
        "Valores de formulários não são coletados; campos sem referência concreta são ignorados.",
        "Deduplicação por URL canônica, parâmetro e contexto; valores distintos são alvos distintos.",
        "max-pages limita respostas da descoberta; sondas SQLi usam o orçamento global restante.",
        "Perfis textuais LIKE/igualdade entre aspas; sem SQLi numérica, temporal, UNION ou escrita.",
        "not_detected não prova segurança; instabilidade ou erros podem tornar a análise inconclusiva.",
        "Ctrl+C preserva o que foi coletado quando possível; encerramento forçado pode perder o último parâmetro.",
    ])

    def save():
        if checkpoint:
            checkpoint(report)

    with ScopedHttpClient(report.target, report.requests, timeout=timeout, max_requests=max_requests,
                          interval=interval, max_body_bytes=max_body_bytes) as client:
        save()  # Também detecta destino de saída inválido antes do tráfego.
        try:
            crawl(discovery, client)
            collect_targets(report)
            report.ignored_targets.extend(discovery.ignored_targets)
            save()
            client.phase = "analysis"
            for target in report.targets:
                required = samples + EXTRA_REQUESTS
                if client.max_requests - client.request_count < required:
                    target["status"] = "skipped"
                    report.ignored_targets.append({**target, "reason": "insufficient_global_budget",
                                                   "required_requests": required,
                                                   "remaining_requests": client.max_requests - client.request_count})
                    if "max_requests" not in report.stop_reasons:
                        report.stop_reasons.append("max_requests")
                    continue
                analysis = ScanReport(target["url"], utc_now(), {
                    "samples": samples, "parameter": target["parameter"], "context": context,
                    "scope": "same_origin_loopback", "planned_requests": required,
                    "max_requests": max_requests, "shared_global_budget": True,
                }, mode="sqli", schema_version="1.2",
                    target_source="automatic" if any(source["kind"] != "manual" for source in target["sources"]) else "manual")
                report.analyses.append(analysis)
                target["status"] = "running"
                plan = build_probe_plan(target["url"], samples, required, parameter=target["parameter"],
                                        context=context, start_id=client.request_count + 1)
                try:
                    run_detection(client, analysis, plan)
                finally:
                    analysis.finished_at = utc_now()
                target["status"] = "completed"
                save()
        except KeyboardInterrupt:
            report.status = "interrupted"
            report.stop_reasons.append("user_interrupt")
            if not report.targets:
                collect_targets(report)
                report.ignored_targets.extend(discovery.ignored_targets)
            for target in report.targets:
                if target["status"] in {"pending", "running"}:
                    target["status"] = "interrupted" if target["status"] == "running" else "skipped"
                    report.ignored_targets.append({**target, "reason": "user_interrupt"})
        finally:
            report.stop_reasons = list(dict.fromkeys([*report.stop_reasons, *discovery.stop_reasons]))
            if report.status != "interrupted":
                failed = discovery.errors or any(
                    analysis.errors or analysis.assessment.outcome == "inconclusive" for analysis in report.analyses
                )
                report.status = "incomplete" if failed else "limited" if report.stop_reasons else "completed"
            report.finished_at = utc_now()
            save()
    return report
