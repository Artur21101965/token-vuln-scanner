from src.verifiers.confidence import score_confidence, filter_by_confidence, demote_fallback_findings
from src.types import Finding, Severity


def test_score_fallback_only():
    """Contract has fallback, selector not in dispatch => low confidence"""
    score = score_confidence(has_fallback=True, in_dispatch_table=False, eth_call_succeeded=True, selector_based=True)
    assert score < 0.3


def test_score_fallback_with_dispatch():
    """Contract has fallback AND selector in dispatch => moderate confidence"""
    score = score_confidence(has_fallback=True, in_dispatch_table=True, eth_call_succeeded=True, selector_based=True)
    assert 0.2 < score < 0.5


def test_score_no_fallback_with_dispatch():
    """No fallback, selector in dispatch => high confidence"""
    score = score_confidence(has_fallback=False, in_dispatch_table=True, eth_call_succeeded=True, selector_based=True)
    assert score >= 0.7


def test_score_eth_call_reverted():
    """eth_call reverted => very low confidence"""
    score = score_confidence(has_fallback=False, in_dispatch_table=True, eth_call_succeeded=False, selector_based=True)
    assert score < 0.1


def test_score_only_owner_bypassed():
    """owner-only check passed by non-owner => high confidence"""
    score = score_confidence(has_fallback=False, in_dispatch_table=True, eth_call_succeeded=True, only_owner_bypassed=True, selector_based=True)
    assert score >= 0.9


def test_score_non_selector():
    """Checks not based on selectors always get 1.0"""
    score = score_confidence(selector_based=False)
    assert score == 1.0


def test_filter_removes_low_confidence():
    f = Finding(check_name="test", severity=Severity.CRITICAL, description="", recommendation="")
    result = filter_by_confidence([f], {id(f): 0.2})
    assert len(result) == 0


def test_filter_keeps_high_confidence():
    f = Finding(check_name="test", severity=Severity.CRITICAL, description="", recommendation="")
    result = filter_by_confidence([f], {id(f): 0.8})
    assert len(result) == 1


def test_demote_fallback_finding():
    """Demote severity for low-confidence findings"""
    f = Finding(check_name="test", severity=Severity.CRITICAL, description="", recommendation="")
    result = demote_fallback_findings([f], {id(f): 0.2})
    assert len(result) == 1


def test_demote_preserves_high_confidence():
    f = Finding(check_name="test", severity=Severity.CRITICAL, description="", recommendation="")
    result = demote_fallback_findings([f], {id(f): 0.9})
    assert len(result) == 1
    assert result[0].severity == Severity.CRITICAL  # unchanged
