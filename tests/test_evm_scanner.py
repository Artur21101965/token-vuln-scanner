import pytest
from unittest.mock import Mock
from src.scanners.base import BaseCheck, CheckContext, BaseScanner
from src.scanners.evm_scanner import EvmScanner
from src.types import TokenInfo, PoolInfo, Chain, Severity, Finding
from src.data import DataCollector
from src.rpc import RpcClient


class DummyCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "dummy_check"
    @property
    def severity(self) -> Severity:
        return Severity.INFO
    @property
    def description(self) -> str:
        return "Dummy check"
    @property
    def recommendation(self) -> str:
        return "Do nothing"
    def run(self, ctx: CheckContext):
        return Finding(
            check_name=self.name,
            severity=self.severity,
            description=self.description,
            recommendation=self.recommendation,
        )


class NullCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "null_check"
    @property
    def severity(self) -> Severity:
        return Severity.LOW
    @property
    def description(self) -> str:
        return "Always returns None"
    @property
    def recommendation(self) -> str:
        return "Nothing"
    def run(self, ctx: CheckContext):
        return None


def test_base_check_interface():
    check = DummyCheck()
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=1000),
        data_collector=Mock(spec=DataCollector),
        rpc=Mock(spec=RpcClient),
    )
    result = check.run(ctx)
    assert result is not None
    assert result.check_name == "dummy_check"
    assert result.severity == Severity.INFO


def test_base_scanner_collects_findings():
    class TestScanner(BaseScanner):
        @property
        def checks(self):
            return [DummyCheck(), NullCheck()]

    scanner = TestScanner(data_collector=Mock(), rpc=Mock())
    token = TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM)
    pool = PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=1000)
    report = scanner.scan(token, pool)
    assert len(report.findings) == 1  # DummyCheck returns, NullCheck returns None
    assert report.findings[0].check_name == "dummy_check"


def test_base_scanner_handles_check_error():
    class BrokenCheck(BaseCheck):
        @property
        def name(self) -> str:
            return "broken"
        @property
        def severity(self) -> Severity:
            return Severity.CRITICAL
        @property
        def description(self) -> str:
            return ""
        @property
        def recommendation(self) -> str:
            return ""
        def run(self, ctx):
            raise ValueError("oops")

    class TestScanner(BaseScanner):
        @property
        def checks(self):
            return [BrokenCheck()]

    scanner = TestScanner(data_collector=Mock(), rpc=Mock())
    token = TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM)
    pool = PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=1000)
    report = scanner.scan(token, pool)
    assert len(report.findings) == 1
    assert "error" in report.findings[0].description.lower()


def test_evm_scanner_creates():
    scanner = EvmScanner(data_collector=Mock(), rpc=Mock())
    assert len(scanner.checks) == 4  # ownership + mint + lp_safety + honeypot checks registered
