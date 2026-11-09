"""Counts preserve abstentions; repetitions are descriptive, not independent trials."""
from collections import Counter, defaultdict
import statistics

OUTCOMES = {"confirmed", "suspected", "inconclusive", "not_detected", "reflected_safe", "not_evaluated"}


def cell(truth, outcome, module, *, method="A"):
    if outcome == "not_evaluated":
        return "not_evaluated"
    if truth == "mitigated" or truth == "unknown":
        return "outside_binary"
    if method == "B":
        positive, negative = outcome == "positive", outcome == "negative"
    else:
        if outcome not in OUTCOMES or outcome == "reflected_safe" and module != "xss":
            raise ValueError("Unsupported detector outcome")
        positive = outcome == "confirmed"
        negative = outcome == "not_detected" or module == "xss" and outcome == "reflected_safe"
    if positive:
        return "TP" if truth == "vulnerable" else "FP"
    if negative:
        return "FN" if truth == "vulnerable" else "TN"
    return "suspected" if outcome == "suspected" else "inconclusive"


def ratio(numerator, denominator):
    return dict(numerator=numerator, denominator=denominator,
                value=numerator / denominator if denominator else None,
                undefined_reason=None if denominator else "denominator_zero")


def summarize(rows, *, method="A"):
    counts = Counter(cell(r["truth"], r["outcome"] if method == "A" else r["baseline"], r["module"], method=method) for r in rows)
    counts = {key: counts[key] for key in ("TP", "FP", "TN", "FN", "suspected", "inconclusive", "not_evaluated", "outside_binary")}
    tp, fp, tn, fn = (counts[k] for k in ("TP", "FP", "TN", "FN"))
    evaluated = len(rows) - counts["not_evaluated"]
    vulnerable = sum(r["truth"] == "vulnerable" for r in rows)
    observed = Counter(r["outcome"] if method == "A" else r["baseline"] for r in rows)
    return dict(planned=len(rows), evaluated=evaluated, counts=counts,
        expected=dict(Counter(r["truth"] for r in rows)),
        observed=dict(observed),
        precision=ratio(tp, tp+fp), recall=ratio(tp, tp+fn), specificity=ratio(tn, tn+fp),
        false_positive_rate=ratio(fp, fp+tn), coverage=ratio(evaluated, len(rows)),
        inconclusive_rate=ratio(observed["inconclusive"], evaluated), suspected_rate=ratio(observed["suspected"], evaluated),
        confirmation_yield=ratio(tp, vulnerable))


def grouped(rows):
    groups = defaultdict(list)
    identities = set()
    for row in rows:
        key = tuple(row[k] for k in ("evaluation_id", "case_id", "condition", "repetition", "unit_id"))
        if key in identities:
            raise ValueError("Duplicate evaluation unit")
        identities.add(key)
        if row["truth"] == "unknown":
            continue  # Automatic inventory has no predeclared full-app denominator.
        groups[(row["domain"], row["module"], row["condition"], row["stratum"])].append(row)
    return [{"domain": key[0], "module": key[1], "condition": key[2], "stratum": key[3],
             "A": summarize(values), "B": summarize(values, method="B")} for key, values in sorted(groups.items())]


def describe(values):
    values = [value for value in values if value is not None]
    return dict(n=len(values), minimum=min(values) if values else None,
                median=statistics.median(values) if values else None, maximum=max(values) if values else None,
                sample_stdev=statistics.stdev(values) if len(values) >= 2 else None)


def repeatability(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[(row["case_id"], row["condition"], row["unit_id"])].append(row)
    result = []
    for key, values in sorted(groups.items()):
        observed = [r["outcome"] for r in values if r["outcome"] != "not_evaluated"]
        counts = Counter(observed)
        result.append(dict(case_id=key[0], condition=key[1], unit_id=key[2], planned=len(values), evaluated=len(observed),
            outcomes=dict(counts), modal_frequency=max(counts.values()) / len(observed) if len(observed) >= 2 else None,
            all_three_consistent=len(observed) == 3 and len(counts) == 1,
            wall_seconds=describe(r["wall_seconds"] for r in values if r["outcome"] != "not_evaluated"),
            requests=describe(r["requests"] for r in values if r["outcome"] != "not_evaluated")))
    return result
