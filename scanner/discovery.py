"""Crawler HTML GET restrito à origem local, sem payloads e sem submeter formulários."""

from collections import deque
from dataclasses import asdict, dataclass, field
from email.message import Message
from html.parser import HTMLParser
import re
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

from scanner.http_client import HttpClient, HttpClientError
from scanner.models import (
    DiscoveredEndpoint, DiscoveryReport, DiscoverySource, EndpointParameter, RequestFailure, utc_now,
)
from scanner.targets import TargetError, validate_target

UNRESERVED = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")


def normalize_url(reference: str, base: str | None = None) -> str:
    """Resolve referências e canonicaliza sem decodificar separadores reservados."""
    if any(ord(char) < 32 or char == "\\" for char in reference):
        raise TargetError("URL contém caractere de controle ou barra invertida.")
    try:
        absolute = urljoin(base, reference) if base is not None else reference
        raw = urlsplit(absolute)
        checked = urlsplit(validate_target(urlunsplit(raw._replace(fragment=""))))
        port = checked.port
        host = f"[{checked.hostname}]" if ":" in checked.hostname else checked.hostname
        authority = host if port in (None, 80 if checked.scheme == "http" else 443) else f"{host}:{port}"

        def percent(match):
            character = chr(int(match.group(1), 16))
            return character if character in UNRESERVED else "%" + match.group(1).upper()

        path = re.sub(r"%(?![0-9a-fA-F]{2})", "%25", checked.path)
        path = re.sub(r"%([0-9a-fA-F]{2})", percent, path)
        segments = []
        parts = path.split("/")
        for index, segment in enumerate(parts):
            if segment in {".", ".."}:
                if segment == ".." and len(segments) > 1:
                    segments.pop()
                if index == len(parts) - 1:
                    segments.append("")
            else:
                segments.append(segment)
        path = quote("/".join(segments) or "/", safe="/:@!$&'()*+,;=-._~%")
        # Ordena nomes; mantém a ordem dos valores de parâmetros repetidos.
        pairs = parse_qsl(checked.query, keep_blank_values=True, max_num_fields=200)
        query = urlencode(sorted(pairs, key=lambda pair: pair[0]))
        return urlunsplit((checked.scheme, authority, path, query, ""))
    except TargetError:
        raise
    except ValueError as error:
        raise TargetError("Referência de URL inválida.") from error


def origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    return parts.scheme, parts.hostname, parts.port or (80 if parts.scheme == "http" else 443)


@dataclass
class HtmlForm:
    action: str
    method: str
    identifier: str
    fields: list[EndpointParameter] = field(default_factory=list)


class HtmlInventoryParser(HTMLParser):
    """Extrai atributos estáticos; não executa scripts nem monta um DOM."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[HtmlForm] = []
        self.base_href: str | None = None
        self._active_forms: list[HtmlForm] = []
        self._associated_fields: list[tuple[str, EndpointParameter]] = []

    def handle_starttag(self, tag, attributes):
        attrs = {}
        for name, value in attributes:
            attrs.setdefault(name, value)
        if tag == "base" and "href" in attrs and self.base_href is None:
            self.base_href = attrs["href"] or ""
        if tag in {"a", "area"} and "href" in attrs:
            self.links.append(attrs["href"] or "")
        if tag == "form":
            form = HtmlForm(attrs.get("action") or "", (attrs.get("method") or "get").lower(), attrs.get("id") or "")
            self.forms.append(form)
            self._active_forms.append(form)
        if tag in {"input", "select", "textarea", "button"} and attrs.get("name") and "disabled" not in attrs:
            parameter = EndpointParameter(attrs["name"], "form", (attrs.get("type") or "text").lower() if tag == "input" else tag)
            if "form" in attrs:
                self._associated_fields.append((attrs["form"], parameter))
            elif self._active_forms:
                self._active_forms[-1].fields.append(parameter)

    def handle_endtag(self, tag):
        if tag == "form" and self._active_forms:
            self._active_forms.pop()

    def close(self):
        super().close()
        for identifier, parameter in self._associated_fields:
            form = next((form for form in self.forms if form.identifier == identifier), None)
            if form is not None:
                form.fields.append(parameter)


def new_discovery_report(
    url: str, *, max_depth: int = 2, max_pages: int = 20, max_requests: int = 20,
    timeout: float = 5.0, interval: float = 0.2, max_body_bytes: int = 1_048_576,
) -> DiscoveryReport:
    target = normalize_url(url)
    if max_depth < 0 or max_pages < 1 or max_requests < 1:
        raise ValueError("Profundidade deve ser não negativa; limites de páginas e requisições devem ser positivos.")
    return DiscoveryReport(target, utc_now(), {
        "max_depth": max_depth, "max_pages": max_pages, "max_requests": max_requests,
        "timeout_seconds": timeout, "interval_seconds": interval, "max_body_bytes": max_body_bytes,
        "scope": "same_origin_loopback", "follow_redirects": False, "submit_forms": False,
    })


def crawl(report: DiscoveryReport, client: HttpClient) -> None:
    """Preenche o inventário usando um cliente existente; não fecha sua sessão."""
    target = report.target
    max_depth, max_pages, max_requests = (report.settings[key] for key in ("max_depth", "max_pages", "max_requests"))
    scope = origin(target)
    initial_count = client.request_count
    endpoints: dict[str, DiscoveredEndpoint] = {}
    pending = deque([(target, 0)])
    scheduled = {target}

    def skip(reason: str, reference=None, page_url=None) -> None:
        report.skipped[reason] = report.skipped.get(reason, 0) + 1
        report.ignored_targets.append({"url": reference, "source_page": page_url, "reason": reason})

    def stop(reason: str) -> None:
        if reason not in report.stop_reasons:
            report.stop_reasons.append(reason)

    def record(reference: str, base: str, source: DiscoverySource, fields=()) -> str | None:
        try:
            candidate = normalize_url(reference, base)
        except TargetError:
            skip("invalid_or_non_loopback_url", reference, source.page_url)
            return None
        if origin(candidate) != scope:
            skip("different_origin", candidate, source.page_url)
            return None
        parts = urlsplit(candidate)
        key = urlunsplit(parts._replace(query=""))
        if key not in endpoints:
            endpoints[key] = DiscoveredEndpoint(key)
            report.endpoints.append(endpoints[key])
        endpoint = endpoints[key]
        if candidate not in endpoint.observed_urls:
            endpoint.observed_urls.append(candidate)
        parameters = [EndpointParameter(name, "query") for name, _ in parse_qsl(parts.query, keep_blank_values=True)]
        for parameter in [*parameters, *fields]:
            if parameter not in endpoint.parameters:
                endpoint.parameters.append(parameter)
        if source not in endpoint.sources:
            endpoint.sources.append(source)
        report.candidates.append({"url": candidate, "method": "GET", "source": asdict(source),
                                  "form_parameters": [parameter.name for parameter in fields]})
        return candidate

    record(target, target, DiscoverySource("manual", None, 0))
    try:
        while pending:
            if len(report.pages) >= max_pages or client.request_count - initial_count >= max_requests or client.request_count >= client.max_requests:
                if len(report.pages) >= max_pages:
                    stop("max_pages")
                if client.request_count - initial_count >= max_requests or client.request_count >= client.max_requests:
                    stop("max_requests")
                break
            current, depth = pending.popleft()
            before = client.request_count
            try:
                response = client.get(current)
            except HttpClientError as error:
                report.errors.append(error.failure)
                continue
            except KeyboardInterrupt:
                if client.request_count > before:
                    report.errors.append(RequestFailure(client.request_count, current, "interrupted", "Descoberta interrompida pelo usuário."))
                raise
            report.pages.append({**response.to_dict(), "depth": depth})
            media = Message()
            media["Content-Type"] = response.content_type
            if not 200 <= response.status_code < 300 or media.get_content_type() not in {"text/html", "application/xhtml+xml"}:
                continue
            try:
                html = response.body.decode(media.get_content_charset() or "utf-8", errors="replace")
            except LookupError:
                html = response.body.decode("utf-8", errors="replace")
            parser = HtmlInventoryParser()
            parser.feed(html)
            parser.close()
            base = current
            if parser.base_href is not None:
                # Base externa continua externa: referências relativas serão bloqueadas.
                if any(ord(char) < 32 or char == "\\" for char in parser.base_href):
                    skip("invalid_base")
                else:
                    try:
                        base = urljoin(current, parser.base_href)
                    except ValueError:
                        skip("invalid_base")
            for href in parser.links:
                candidate = record(href, base, DiscoverySource("html_link", current, depth + 1))
                if candidate is None or candidate in scheduled:
                    continue
                if depth + 1 > max_depth:
                    stop("max_depth")
                    continue
                scheduled.add(candidate)
                pending.append((candidate, depth + 1))
            for form in parser.forms:
                if form.method != "get":
                    skip("unsupported_form_method", form.action, current)
                    continue
                record(form.action or current, base, DiscoverySource("get_form", current, depth + 1), form.fields)
    finally:
        report.requests_attempted = client.request_count - initial_count
        report.queued_remaining = len(pending)
        report.finished_at = utc_now()


def discover(
    url: str, *, max_depth: int = 2, max_pages: int = 20, max_requests: int = 20,
    timeout: float = 5.0, interval: float = 0.2, max_body_bytes: int = 1_048_576,
) -> DiscoveryReport:
    report = new_discovery_report(url, max_depth=max_depth, max_pages=max_pages, max_requests=max_requests,
                                  timeout=timeout, interval=interval, max_body_bytes=max_body_bytes)
    with HttpClient(timeout, max_requests, interval, max_body_bytes) as client:
        crawl(report, client)
    return report
