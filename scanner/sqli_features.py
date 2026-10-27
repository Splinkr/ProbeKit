"""Características reproduzíveis de JSON, HTML e texto, sem persistir conteúdo."""

from dataclasses import replace
from email.message import Message
import hashlib
from html.parser import HTMLParser
import json
import re

from scanner.models import ProbeEvidence, ResponseEvidence, ResponseFeatures

SIGNATURES = ("SQLITE_ERROR", "SQLITE_MISUSE", "SequelizeDatabaseError")
ERROR_TEXT = re.compile(r"^(?:error(?:\b|:)|internal server error|not found|forbidden|service unavailable)", re.I)


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


class VisibleHtml(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.title = []
        self._ignored = 0
        self._title = False

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self._ignored += 1
        if tag == "title":
            self._title = True

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self._ignored:
            self._ignored -= 1
        if tag == "title":
            self._title = False

    def handle_data(self, data):
        if not self._ignored:
            self.text.append(data)
            if self._title:
                self.title.append(data)


def extract_features(response: ResponseEvidence) -> ResponseFeatures:
    header = Message()
    header["Content-Type"] = response.content_type
    media = header.get_content_type()
    healthy = 200 <= response.status_code < 300
    if media == "application/json" or media.endswith("+json"):
        try:
            payload = json.loads(response.body)
        except (ValueError, UnicodeError, RecursionError):
            return ResponseFeatures("json", "invalid_json", None, None, False, False, True)
        error = isinstance(payload, dict) and (payload.get("status") in ("error", "failed") or bool(payload.get("error")))
        rows = payload if isinstance(payload, list) else next(
            (payload[key] for key in ("data", "items", "results") if isinstance(payload.get(key), list)), None
        ) if isinstance(payload, dict) else None
        if rows is not None:
            for key in ("id", "sku", "code"):
                if rows and all(isinstance(row, dict) and type(row.get(key)) in (int, str) for row in rows):
                    ids = [row[key] for row in rows]
                    if len({(type(value).__name__, value) for value in ids}) == len(ids):
                        ordered = sorted(ids) if all(type(value) is int for value in ids) else sorted(ids, key=lambda value: (type(value).__name__, str(value)))
                        return ResponseFeatures("json", f"collection_ids:{key}", digest(ordered), len(rows), bool(rows), healthy and not error, error)
            canonical = sorted((json.dumps(row, sort_keys=True, ensure_ascii=False) for row in rows))
            # [] também é a identidade da coleção vazia nos casos com IDs.
            fingerprint = digest(canonical)
            return ResponseFeatures("json", "collection_values", fingerprint, len(rows), bool(rows), healthy and not error, error)
        usable = payload is not None and isinstance(payload, (dict, str, int, float, bool))
        return ResponseFeatures("json", "canonical_json", digest(payload), None, bool(payload), healthy and usable and not error, error)
    if media not in {"text/html", "application/xhtml+xml", "text/plain"}:
        return ResponseFeatures("unsupported", "unsupported_media_type", None, None, False, False)
    try:
        text = response.body.decode(header.get_content_charset() or "utf-8", errors="replace")
    except LookupError:
        text = response.body.decode("utf-8", errors="replace")
    kind, strategy = "text", "normalized_text"
    title = ""
    if media != "text/plain":
        parser = VisibleHtml()
        parser.feed(text)
        parser.close()
        text, title = " ".join(parser.text), " ".join(parser.title).strip()
        kind, strategy = "html", "visible_text"
    text = " ".join(text.split())
    error = bool(ERROR_TEXT.search(title) or ERROR_TEXT.search(text))
    return ResponseFeatures(kind, strategy, digest(text), None, bool(text), healthy and not error, error)


def observe(probe: ProbeEvidence, response: ResponseEvidence) -> ProbeEvidence:
    signatures = [token for token in SIGNATURES if token.encode() in response.body]
    features = extract_features(response)
    count, fingerprint = None, None
    # Campos legados preservados para relatórios/experimentos de produtos.
    if response.status_code == 200 and response.content_type.split(";", 1)[0].strip().lower() == "application/json":
        try:
            payload = json.loads(response.body)
            rows = payload.get("data") if isinstance(payload, dict) else None
            if (isinstance(payload, dict) and payload.get("status") == "success" and isinstance(rows, list)
                    and all(isinstance(row, dict) and type(row.get("id")) is int and isinstance(row.get("name"), str) for row in rows)):
                ids = sorted(row["id"] for row in rows)
                if len(ids) == len(set(ids)):
                    count, fingerprint = len(ids), digest(ids)
        except (ValueError, UnicodeError, RecursionError):
            pass
    return replace(probe, response_received=True, product_count=count,
                   product_ids_sha256=fingerprint, sql_error_signatures=signatures, features=features)
