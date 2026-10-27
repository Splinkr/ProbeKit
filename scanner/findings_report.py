"""Projeção dos achados existentes; não executa nem reclassifica sondas."""

import re
from typing import Any
from urllib.parse import unquote_plus, urlsplit, urlunsplit


VULNERABILITY_TYPES = {
    "sqli": "sql_injection",
    "xss": "reflected_xss",
    "exposure": "sensitive_file_exposure",
}
STATUSES = ("confirmed", "suspected")
SENSITIVE_NAMES = re.compile(
    r"password|passwd|pwd|secret|token|apikey|accesskey|privatekey|"
    r"authorization|credential|cookie|session|signature|csrf|xsrf|jwt|bearer|^auth$|^key$|^sig$"
)


def _safe_url(url: str) -> tuple[str, bool]:
    """Preserva a URL, mascarando credenciais e valores de parâmetros sensíveis."""
    parts = urlsplit(url)
    query = []
    for item in parts.query.split("&"):
        name, separator, value = item.partition("=")
        normalized = re.sub(r"[^a-z0-9]", "", unquote_plus(name).lower())
        if separator and SENSITIVE_NAMES.search(normalized):
            value = "%5BREDACTED%5D"
        query.append(name + separator + value)
    safe = urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[-1], parts.path,
                       "&".join(query), ""))
    return safe, safe != url


def build_findings_report(data: dict[str, Any], source_report: str) -> dict[str, Any]:
    """Usa somente Finding dos módulos, evitando cópias em resultados consolidados."""
    analyses = data.get("analyses", []) if data.get("mode") == "scan" else [data]
    unique = {}
    for analysis in analyses:
        for finding in analysis.get("findings", []):
            module = finding["category"]
            status = finding["status"]
            if module not in VULNERABILITY_TYPES or status not in STATUSES:
                continue
            # Deduplicação antes de mascarar a URL: valores distintos não se confundem.
            key = (module, finding["endpoint"], finding.get("parameter"), status)
            if key in unique:
                unique[key]["evidence_request_ids"] = sorted(set(
                    unique[key]["evidence_request_ids"] + finding["evidence_request_ids"]
                ))
                continue
            url, redacted = _safe_url(finding["endpoint"])
            unique[key] = {
                "module": module,
                "vulnerability_type": VULNERABILITY_TYPES[module],
                "url": url,
                "url_redacted": redacted,
                "parameter": finding.get("parameter"),
                "status": status,
                "confidence": finding.get("confidence"),
                "evidence": finding["rationale"],
                "evidence_request_ids": sorted(set(finding["evidence_request_ids"])),
                "potential_impact": finding["potential_impact"],
                "recommended_mitigation": finding["recommended_mitigation"],
            }
    findings = list(unique.values())

    def counts(items):
        return {"total": len(items), **{status: sum(item["status"] == status for item in items)
                                       for status in STATUSES}}

    return {
        "schema_version": "1.0",
        "report_type": "security_findings",
        "source_report": source_report,
        "scan_status": data.get("summary", {}).get("status"),
        "started_at": data.get("started_at"),
        "finished_at": data.get("finished_at"),
        "summary": {**counts(findings), "by_module": {
            module: counts([item for item in findings if item["module"] == module])
            for module in VULNERABILITY_TYPES
        }},
        "findings": findings,
    }
