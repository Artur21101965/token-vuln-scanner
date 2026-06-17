from src.types import Finding, Severity

CONFIDENCE_THRESHOLD = 0.5


def score_confidence(
    has_fallback: bool = False,
    in_dispatch_table: bool = False,
    eth_call_succeeded: bool = True,
    only_owner_bypassed: bool = False,
    selector_based: bool = True,
) -> float:
    if not selector_based:
        return 1.0

    if has_fallback:
        if not in_dispatch_table:
            return 0.0
        if eth_call_succeeded:
            return 0.3
        return 0.0

    if not in_dispatch_table:
        return 0.1
    if not eth_call_succeeded:
        return 0.0
    if only_owner_bypassed:
        return 0.9
    return 0.7


def filter_by_confidence(findings: list[Finding], scores: dict[int, float]) -> list[Finding]:
    return [f for f in findings if scores.get(id(f), 1.0) >= CONFIDENCE_THRESHOLD]


def demote_fallback_findings(findings: list[Finding], scores: dict[int, float]) -> list[Finding]:
    result = []
    for f in findings:
        score = scores.get(id(f), 1.0)
        if score < 0.3 and f.severity.value > 0:
            new_val = max(f.severity.value - 1, 0)
            f.severity = Severity(new_val)
        result.append(f)
    return result
