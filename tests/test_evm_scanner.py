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

    data = Mock()
    data.get_code.return_value = ""
    data.fallback_detected.return_value = False
    scanner = TestScanner(data_collector=data, rpc=Mock())
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

    data = Mock()
    data.get_code.return_value = ""
    data.fallback_detected.return_value = False
    scanner = TestScanner(data_collector=data, rpc=Mock())
    token = TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM)
    pool = PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=1000)
    report = scanner.scan(token, pool)
    assert len(report.findings) == 1
    assert "error" in report.findings[0].description.lower()


def test_parallel_checks_collect_all_findings():
    """All check results are collected when running in parallel."""
    class TestScanner(BaseScanner):
        @property
        def checks(self):
            return [DummyCheck(), DummyCheck()]

    data = Mock()
    data.get_code.return_value = ""
    data.fallback_detected.return_value = False
    scanner = TestScanner(data_collector=data, rpc=Mock())
    token = TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM)
    pool = PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=1000)
    report = scanner.scan(token, pool)
    assert len(report.findings) == 2


def test_parallel_checks_handles_error():
    """One failing check doesn't affect other checks in parallel mode."""
    class FailCheck(BaseCheck):
        @property
        def name(self): return "fail"
        @property
        def severity(self): return Severity.CRITICAL
        @property
        def description(self): return ""
        @property
        def recommendation(self): return ""
        def run(self, ctx): raise ValueError("fail")

    class TestScanner(BaseScanner):
        @property
        def checks(self):
            return [FailCheck(), DummyCheck()]

    data = Mock()
    data.get_code.return_value = ""
    data.fallback_detected.return_value = False
    scanner = TestScanner(data_collector=data, rpc=Mock())
    token = TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM)
    pool = PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=1000)
    report = scanner.scan(token, pool)
    assert len(report.findings) == 2  # error finding + dummy finding


def test_evm_scanner_creates():
    data = Mock()
    data.get_code.return_value = ""
    data.fallback_detected.return_value = False
    scanner = EvmScanner(data_collector=data, rpc=Mock())
    assert len(scanner.checks) == 45  # +storage_collision +unchecked_erc20


def test_confidence_filters_fallback_false_positive():
    """Forwarding contract with fallback but no dispatch selectors should filter selector-based findings."""
    class SelectorCheck(BaseCheck):
        @property
        def name(self): return "withdraw_check"
        @property
        def severity(self): return Severity.CRITICAL
        @property
        def description(self): return "Withdraw function detected"
        @property
        def recommendation(self): return "Review"
        def run(self, ctx):
            f = Finding(check_name=self.name, severity=self.severity,
                       description=self.description, recommendation=self.recommendation)
            f._selector_based = True  # marked by check
            return f

    class TestScanner(BaseScanner):
        @property
        def checks(self): return [SelectorCheck()]

    data = Mock()
    data.get_code.return_value = "0x60006000fd"  # simple bytecode (no dispatch table)
    data.fallback_detected.return_value = True  # has fallback
    scanner = TestScanner(data_collector=data, rpc=Mock())
    token = TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM)
    pool = PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=1000)
    report = scanner.scan(token, pool)
    # Low confidence findings should be filtered out
    assert len(report.findings) == 0, f"Expected 0 findings, got {len(report.findings)}"


def test_confidence_keeps_high_confidence():
    """Contract without fallback should keep selector-based findings."""
    class SelectorCheck(BaseCheck):
        @property
        def name(self): return "mint_check"
        @property
        def severity(self): return Severity.HIGH
        @property
        def description(self): return "Mint function detected"
        @property
        def recommendation(self): return "Review"
        def run(self, ctx):
            f = Finding(check_name=self.name, severity=self.severity,
                       description=self.description, recommendation=self.recommendation)
            f._selector_based = True
            return f

    class TestScanner(BaseScanner):
        @property
        def checks(self): return [SelectorCheck()]

    data = Mock()
    # Bytecode with a dispatch table so dispatch_selectors is non-empty
    data.get_code.return_value = "0x" + "".join([
        "6000", "35", "600e", "1c", "80",
        "6340c10f19", "14", "610100", "57",
        "fd",
    ])
    data.fallback_detected.return_value = False  # no fallback
    scanner = TestScanner(data_collector=data, rpc=Mock())
    token = TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM)
    pool = PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=1000)
    report = scanner.scan(token, pool)
    assert len(report.findings) == 1
    assert report.findings[0].confidence >= 0.7


def test_confidence_preserves_non_selector():
    """Non-selector-based findings (e.g., supply/balance checks) should always pass through."""
    class NonSelectorCheck(BaseCheck):
        @property
        def name(self): return "supply_check"
        @property
        def severity(self): return Severity.MEDIUM
        @property
        def description(self): return "Supply issue"
        @property
        def recommendation(self): return "Review"
        def run(self, ctx):
            return Finding(check_name=self.name, severity=self.severity,
                         description=self.description, recommendation=self.recommendation)
            # No _selector_based flag = non-selector

    class TestScanner(BaseScanner):
        @property
        def checks(self): return [NonSelectorCheck()]

    data = Mock()
    data.get_code.return_value = ""
    data.fallback_detected.return_value = True
    scanner = TestScanner(data_collector=data, rpc=Mock())
    token = TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM)
    pool = PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=1000)
    report = scanner.scan(token, pool)
    assert len(report.findings) == 1  # non-selector should survive
    assert report.findings[0].confidence == 1.0
