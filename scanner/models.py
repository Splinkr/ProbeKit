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

    @property
    def reachable(self) -> bool:
        return bool(self.responses)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "target": self.target,
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
        }
