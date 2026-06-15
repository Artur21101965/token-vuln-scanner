import pytest
from src.types import (
    TokenInfo, PoolInfo, Finding, Severity, CheckResult, ScanReport, Chain
)


def test_severity_order():
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.LOW > Severity.INFO


def test_token_info_defaults():
    token = TokenInfo(address="0xabc", symbol="TEST", chain=Chain.ETHEREUM)
    assert token.address == "0xabc"
    assert token.symbol == "TEST"
    assert token.chain == Chain.ETHEREUM


def test_finding_creation():
    finding = Finding(
        check_name="owner_not_renounced",
        severity=Severity.HIGH,
        description="Owner address is not zero",
        recommendation="Renounce ownership"
    )
    assert finding.check_name == "owner_not_renounced"
    assert finding.severity == Severity.HIGH


def test_scan_report_summary_critical():
    report = ScanReport(
        token=TokenInfo(address="0xabc", symbol="TEST", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap V3", liquidity_usd=5000),
        findings=[
            Finding(check_name="x", severity=Severity.CRITICAL, description="", recommendation=""),
            Finding(check_name="y", severity=Severity.MEDIUM, description="", recommendation=""),
        ]
    )
    assert "CRITICAL" in report.summary


def test_scan_report_summary_clean():
    report = ScanReport(
        token=TokenInfo(address="0xabc", symbol="TEST", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap V3", liquidity_usd=5000),
        findings=[]
    )
    assert report.summary == "✅ No vulnerabilities found"


def test_chain_from_str():
    assert Chain.from_str("ethereum") == Chain.ETHEREUM
    assert Chain.from_str("bsc") == Chain.BSC
    assert Chain.from_str("solana") == Chain.SOLANA
