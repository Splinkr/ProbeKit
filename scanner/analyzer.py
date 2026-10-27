"""Comparação observacional; a classificação de vulnerabilidades virá depois."""

from difflib import SequenceMatcher

from scanner.models import ResponseComparison, ResponseEvidence

SAMPLE_BYTES = 16_384


def compare_responses(baseline: ResponseEvidence, current: ResponseEvidence) -> ResponseComparison:
    """Hash e tamanho cobrem o corpo completo; similaridade usa até 16 KiB."""
    first = baseline.body[:SAMPLE_BYTES]
    second = current.body[:SAMPLE_BYTES]
    return ResponseComparison(
        baseline_request_id=baseline.request_id,
        compared_request_id=current.request_id,
        status_changed=baseline.status_code != current.status_code,
        content_type_changed=baseline.content_type != current.content_type,
        size_delta_bytes=current.size_bytes - baseline.size_bytes,
        body_changed=baseline.body_sha256 != current.body_sha256,
        sample_similarity=round(SequenceMatcher(None, first, second).ratio(), 6),
        compared_sample_bytes=max(len(first), len(second)),
    )
