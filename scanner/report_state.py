"""Metadados aditivos de coleta e avaliação; não executa nem reclassifica detectores."""

from typing import Any


OUTCOMES = ("confirmed", "suspected", "not_detected", "reflected_safe", "inconclusive")
DETECTORS = {"sqli", "xss", "exposure", "scan"}


def analysis_summary(data: dict[str, Any]) -> dict[str, Any]:
    mode = data.get("mode")
    applicable = mode in DETECTORS
    outcomes = dict.fromkeys(OUTCOMES, 0)
    analyses = data.get("analyses", []) if mode == "scan" and "analyses" in data else [data]
    if applicable:
        for analysis in analyses:
            results = [*analysis.get("parameter_results", []), *analysis.get("exposure_results", [])]
            assessments = [result.get("assessment") for result in results] if results else [analysis.get("assessment")]
            for assessment in assessments:
                outcome = assessment.get("outcome") if assessment else None
                if outcome in outcomes:
                    outcomes[outcome] += 1
    return {"applicable": applicable, "evaluations": sum(outcomes.values()),
            "outcomes": outcomes, "has_inconclusive": outcomes["inconclusive"] > 0}


def collection_status(data: dict[str, Any]) -> str:
    """Estado operacional, independente de avaliações inconclusivas."""
    status = data.get("summary", {}).get("status")
    parts = [data, *data.get("analyses", [])]
    if data.get("discovery") is not None:
        parts.append(data["discovery"])
    errors = [error for part in parts for error in part.get("errors", [])]
    if status == "interrupted" or any(error.get("kind") == "interrupted" for error in errors):
        return "interrupted"
    if errors or any(part.get("execution_errors") for part in parts) or "checkpoint_error" in data.get("stop_reasons", []):
        return "incomplete"
    if data.get("finished_at") is None:
        return "running"
    if data.get("stop_reasons"):
        return "limited"
    return "completed"


def with_report_state(data: dict[str, Any]) -> dict[str, Any]:
    return {**data, "collection_status": collection_status(data), "analysis_summary": analysis_summary(data)}
