"""Pre-registered response-difference predictor. No oracle or assessments input."""


def predict(observations, reference_id, required_ids, complete):
    by_id = {row["request_id"]: row for row in observations}
    if not complete or reference_id not in by_id or len(required_ids) < 2 or not set(required_ids) <= by_id.keys():
        return "inconclusive"
    def signature(row):
        return row["status_code"], row["size_bytes"], row["body_sha256"]
    reference = signature(by_id[reference_id])
    return "positive" if any(signature(by_id[i]) != reference for i in required_ids if i != reference_id) else "negative"
