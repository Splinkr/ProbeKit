"""Dados coletados, comparações e contratos para os futuros detectores."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingStatus(StrEnum):
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"


@dataclass(frozen=True)
class ResponseEvidence:
    request_id: int
    url: str
    collected_at: str
    status_code: int
    content_type: str
    size_bytes: int
    body_sha256: str
    elapsed_ms: float
    body: bytes = field(repr=False, compare=False)
    method: str = "GET"
    security_headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        # Conteúdo, cookies e cabeçalhos de autenticação não são persistidos.
        return {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if name != "body"
        }


@dataclass(frozen=True)
class RequestFailure:
    request_id: int
    url: str
    kind: str
    message: str
    collected_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class ResponseComparison:
    baseline_request_id: int
    compared_request_id: int
    status_changed: bool
    content_type_changed: bool
    size_delta_bytes: int
    body_changed: bool
    sample_similarity: float
    compared_sample_bytes: int
    interpretation: str = "Observação de respostas; não confirma vulnerabilidade."


@dataclass(frozen=True)
class Finding:
    """Um detector deverá fornecer evidências e justificativa da classificação."""

    endpoint: str
    category: str
    title: str
    confidence: Confidence
    status: FindingStatus
    evidence_request_ids: list[int]
    rationale: str
    potential_impact: str
    recommended_mitigation: str
    parameter: str | None = None


@dataclass(frozen=True)
class ResponseFeatures:
    format: str
    strategy: str
    fingerprint: str | None
    result_count: int | None
    nonempty: bool
    valid: bool
    error_like: bool = False


@dataclass(frozen=True)
class ProbeEvidence:
    request_id: int
    role: str
    parameter: str
    input_value: str
    response_received: bool = False
    product_count: int | None = None
    product_ids_sha256: str | None = None
    sql_error_signatures: list[str] = field(default_factory=list)
    context: str = "like"
    features: ResponseFeatures | None = None


@dataclass(frozen=True)
class SqliAssessment:
    outcome: str
    checks: dict[str, bool]
    rationale: str
    limitations: list[str]
    parameter: str | None = None
    context: str = "like"


@dataclass(frozen=True)
class XssAssessment:
    outcome: str
    checks: dict[str, bool]
    rationale: str
    limitations: list[str]
    parameter: str | None = None
    context: str = "reflected_xss"
    browser_evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class XssProbeEvidence:
    request_id: int
    role: str
    parameter: str
    input_value: str
    marker: str | None = None
    response_received: bool = False
    content_format: str = "unknown"
    reflections: list[dict[str, Any]] = field(default_factory=list)
    escaping: dict[str, str] = field(default_factory=dict)
    active_script_marker: bool = False


@dataclass(frozen=True)
class ParameterResult:
    parameter: str
    context: str
    assessment: SqliAssessment | XssAssessment
    evidence_request_ids: list[int]


@dataclass
class ScanReport:
    target: str
    started_at: str
    settings: dict[str, Any]
    responses: list[ResponseEvidence] = field(default_factory=list)
    errors: list[RequestFailure] = field(default_factory=list)
    comparisons: list[ResponseComparison] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    finished_at: str | None = None
    schema_version: str = "1.0"
    mode: str = "baseline"
    probes: list[ProbeEvidence | XssProbeEvidence] = field(default_factory=list)
    assessment: SqliAssessment | XssAssessment | None = None
    parameter_results: list[ParameterResult] = field(default_factory=list)
    target_source: str = "manual"

    @property
    def reachable(self) -> bool:
        return bool(self.responses)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "target": self.target,
            "target_source": self.target_source,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "settings": self.settings,
            "summary": {
                "reachable": self.reachable,
                "status": "completed" if not self.errors else "incomplete",
                "requests_attempted": len(self.responses) + len(self.errors),
                "responses_received": len(self.responses),
                "errors": len(self.errors),
                "findings": len(self.findings),
            },
            "responses": [response.to_dict() for response in self.responses],
            "errors": [asdict(error) for error in self.errors],
            "comparisons": [asdict(comparison) for comparison in self.comparisons],
            "findings": [asdict(finding) for finding in self.findings],
            "probes": [asdict(probe) for probe in self.probes],
            "assessment": asdict(self.assessment) if self.assessment else None,
            "parameter_results": [asdict(result) for result in self.parameter_results],
        }


@dataclass(frozen=True)
class EndpointParameter:
    name: str
    location: str
    field_type: str | None = None


@dataclass(frozen=True)
class DiscoverySource:
    kind: str
    page_url: str | None
    depth: int


@dataclass
class DiscoveredEndpoint:
    endpoint: str
    method: str = "GET"
    parameters: list[EndpointParameter] = field(default_factory=list)
    observed_urls: list[str] = field(default_factory=list)
    sources: list[DiscoverySource] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "provided_manually": any(source.kind == "manual" for source in self.sources),
            "discovered_automatically": any(source.kind != "manual" for source in self.sources),
        }


@dataclass
class DiscoveryReport:
    target: str
    started_at: str
    settings: dict[str, Any]
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    pages: list[dict[str, Any]] = field(default_factory=list)
    errors: list[RequestFailure] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)
    stop_reasons: list[str] = field(default_factory=list)
    requests_attempted: int = 0
    queued_remaining: int = 0
    finished_at: str | None = None
    candidates: list[dict[str, Any]] = field(default_factory=list)
    ignored_targets: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0", "mode": "discover", "target": self.target,
            "target_source": "manual", "started_at": self.started_at, "finished_at": self.finished_at,
            "settings": self.settings,
            "summary": {
                "status": "incomplete" if self.errors else "limited" if self.stop_reasons else "completed",
                "reachable": bool(self.pages), "endpoints": len(self.endpoints),
                "pages_fetched": len(self.pages), "requests_attempted": self.requests_attempted,
                "errors": len(self.errors), "queued_remaining": self.queued_remaining,
            },
            "stop_reasons": self.stop_reasons, "skipped": self.skipped,
            "endpoints": [endpoint.to_dict() for endpoint in self.endpoints],
            "pages": self.pages, "errors": [asdict(error) for error in self.errors],
            "candidates": self.candidates, "ignored_targets": self.ignored_targets,
        }


@dataclass
class IntegratedScanReport:
    target: str
    started_at: str
    settings: dict[str, Any]
    discovery: DiscoveryReport
    analyses: list[ScanReport] = field(default_factory=list)
    targets: list[dict[str, Any]] = field(default_factory=list)
    ignored_targets: list[dict[str, Any]] = field(default_factory=list)
    requests: list[dict[str, Any]] = field(default_factory=list)
    stop_reasons: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    status: str = "running"
    finished_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        results = [
            {"url": analysis.target, "module": analysis.mode, **asdict(result)}
            for analysis in self.analyses for result in analysis.parameter_results
        ]
        return {
            "schema_version": "1.0", "mode": "scan", "initial_url": self.target,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "settings": self.settings,
            "summary": {
                "status": self.status, "requests_used": len(self.requests),
                "discovery_requests": sum(item["phase"] == "discovery" for item in self.requests),
                "analysis_requests": sum(item["phase"] == "analysis" for item in self.requests),
                "requests_remaining": self.settings["max_requests"] - len(self.requests),
                "endpoints_discovered": len(self.discovery.endpoints),
                "parameters_analyzed": len(results), "targets_ignored": len(self.ignored_targets),
                "unique_parameters_analyzed": len({(result["url"], result["parameter"]) for result in results}),
                "findings": sum(len(analysis.findings) for analysis in self.analyses),
            },
            "discovery": self.discovery.to_dict(), "targets": self.targets,
            "parameter_results": results,
            "analyses": [analysis.to_dict() for analysis in self.analyses],
            "requests": self.requests, "ignored_targets": self.ignored_targets,
            "stop_reasons": self.stop_reasons, "limitations": self.limitations,
        }
