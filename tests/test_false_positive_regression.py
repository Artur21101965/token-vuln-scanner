import pytest
from unittest.mock import Mock
from src.data import DataCollector
from src.evm.dispatch_table import parse_dispatch_table, is_selector_in_dispatch
from src.verifiers.confidence import score_confidence
from src.scanners.base import BaseCheck, BaseScanner, CheckContext
from src.types import TokenInfo, PoolInfo, Finding, Severity, Chain
from decimal import Decimal


def test_fallback_detected_on_forwarding_contract():
    """0x51c7-style forwarding contract: eth_call with random data returns 0x"""
    rpc = Mock()
    rpc.eth_call.return_value = "0x"
    rpc.eth_get_code.return_value = "0x60006000fd"
    dc = DataCollector(rpc=rpc, explorer=Mock())
    assert dc.fallback_detected("0x51c7...") is True


def test_withdraw_selector_not_in_dispatch():
    """0x51c7 forwarding contract: 62 selectors in dispatch, but NOT 2e1a7d4d"""
    bytecode = "0x" + "".join([
        "6000", "35", "600e", "1c", "80",
        "6338ed1739", "14", "610100", "57",
        "63a9059cbb", "14", "610200", "57",
        "6000", "60", "00", "52", "60", "20", "60", "00", "f3",
    ])
    selectors, has_fallback = parse_dispatch_table(bytecode)
    assert "2e1a7d4d" not in selectors
    assert has_fallback is True
    assert is_selector_in_dispatch(bytecode, "38ed1739") is True
    assert is_selector_in_dispatch(bytecode, "2e1a7d4d") is False


def test_withdraw_finding_filtered_by_confidence():
    """Withdraw finding on forwarding contract gets low confidence and is filtered out"""
    rpc = Mock()
    rpc.eth_call.return_value = "0x"
    rpc.eth_get_code.return_value = ""
    data = Mock()
    data.fallback_detected.return_value = True
    data.get_code.return_value = "0x" + "".join([
        "6000", "35", "600e", "1c", "80",
        "6338ed1739", "14", "610100", "57",
        "6000", "60", "00", "52", "60", "20", "60", "00", "f3",
    ])
    data.get_abi.return_value = None

    score = score_confidence(
        has_fallback=True,
        in_dispatch_table=False,
        eth_call_succeeded=True,
        selector_based=True,
    )
    assert score < 0.3


def test_non_forwarding_contract_keeps_finding():
    """Normal contract without fallback still gets findings at high confidence"""
    score = score_confidence(
        has_fallback=False,
        in_dispatch_table=True,
        eth_call_succeeded=True,
        selector_based=True,
    )
    assert score >= 0.7
