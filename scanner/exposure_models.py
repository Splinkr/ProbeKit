"""Evidência de exposição por lista permitida de metadados; nunca contém corpos ou valores."""

from dataclasses import asdict, dataclass, field

from scanner.models import Finding, RequestFailure


@dataclass(frozen=True)
class ExposureFeatures:
    kind: str
    strong_signature: bool
    is_html: bool
    public_document: bool
    error_like: bool
    assignment_count: int
    section_count: int
    indicators: dict[str, bool]
    normalized_sha256: str


@dataclass(frozen=True)
class ExposureResponse:
    request_id: int
    url: str
    role: str
    collected_at: str
    status_code: int
    content_type: str
    size_bytes: int
    body_sha256: str
    elapsed_ms: float
    features: ExposureFeatures
    method: str = "GET"


@dataclass(frozen=True)
class ExposureAssessment:
    outcome: str
    checks: dict[str, bool]
    rationale: str
    limitations: list[str]
    parameter: None = None
    context: str = "file_exposure"


@dataclass(frozen=True)
class ExposureResult:
    url: str
    profile: str
    expected_kind: str
    assessment: ExposureAssessment
    evidence_request_ids: list[int]


@dataclass
class ExposureReport:
    target: str
    started_at: str
    settings: dict
    responses: list[ExposureResponse] = field(default_factory=list)
    errors: list[RequestFailure] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    exposure_results: list[ExposureResult] = field(default_factory=list)
    assessment: ExposureAssessment | None = None
    finished_at: str | None = None
    target_source: str = "manual"
    mode: str = "exposure"
    # Contratos comuns da CLI/consolidação; arquivo não é parâmetro GET.
    parameter_results: list = field(default_factory=list)
    probes: list = field(default_factory=list)
    comparisons: list = field(default_factory=list)

    @property
    def reachable(self):
        return bool(self.responses)

    def to_dict(self):
        return {
            "schema_version": "1.0", "mode": self.mode, "target": self.target,
            "target_source": self.target_source, "started_at": self.started_at, "finished_at": self.finished_at,
            "settings": self.settings,
            "summary": {"reachable": self.reachable, "status": "incomplete" if self.errors else "completed",
                        "requests_attempted": len(self.responses) + len(self.errors),
                        "responses_received": len(self.responses), "errors": len(self.errors),
                        "files_analyzed": len(self.exposure_results), "findings": len(self.findings)},
            "responses": [asdict(response) for response in self.responses],
            "errors": [asdict(error) for error in self.errors],
            "findings": [asdict(finding) for finding in self.findings],
            "exposure_results": [asdict(result) for result in self.exposure_results],
            "assessment": asdict(self.assessment) if self.assessment else None,
            "parameter_results": [],
        }
