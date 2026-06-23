import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.cross_contract_reentrancy import CrossContractReentrancyCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.data import DataCollector
from src.rpc import RpcClient


def make_ctx(code: str = ""):
    dc = Mock(spec=DataCollector)
    dc.get_code.return_value = code
    return CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=1000),
        data_collector=dc,
        rpc=Mock(spec=RpcClient),
    )


ERC20_WITH_TRANSFER = (
    "0x6080604052600436106102185760003560e01c8063"
    "a9059cbb1461021d57806323b872dd1461025957"
)

CALL_WITH_PANCAKE_ROUTER = (
    "60806040526004361060a9059cbb1461021d57"
    "10ed43c718714eb63d5aa57b78b54704e256024e"
    "f1"  # CALL opcode
)

PLAIN_ERC20 = (
    "60806040526004361060a9059cbb1461021d57"
    "23b872dd1461025957"
)


class TestCrossContractReentrancyCheck:
    check = CrossContractReentrancyCheck()

    def test_name_and_severity(self):
        assert self.check.name == "cross_contract_reentrancy"
        assert self.check.severity == Severity.CRITICAL

    def test_detects_erc20_with_router_call(self):
        code = "0x" + CALL_WITH_PANCAKE_ROUTER
        finding = self.check.run(make_ctx(code=code))
        assert finding is not None
        assert finding.severity in (Severity.CRITICAL, Severity.HIGH)
        assert "router" in finding.description.lower() or "DEX" in finding.description.upper()

    def test_does_not_flag_plain_erc20(self):
        code = "0x" + PLAIN_ERC20
        finding = self.check.run(make_ctx(code=code))
        assert finding is None or finding.severity != Severity.CRITICAL

    def test_returns_none_for_empty_code(self):
        assert self.check.run(make_ctx(code="")) is None
        assert self.check.run(make_ctx(code="0x")) is None

    def test_returns_none_for_tiny_code(self):
        assert self.check.run(make_ctx(code="0x1234")) is None

    def test_detects_router_without_erc20(self):
        code = "0x" + "10ed43c718714eb63d5aa57b78b54704e256024e" + "f1"
        finding = self.check.run(make_ctx(code=code))
        assert finding is not None
        # Should be HIGH (router + CALL, but no ERC20)
        assert finding.severity in (Severity.HIGH, Severity.CRITICAL)

    def test_pancakeswap_router_in_bytecode(self):
        code = ("0x" + "608060405260043610" + "10ed43c718714eb63d5aa57b78b54704e256024e"
                + "a9059cbb" + "f1" * 3)
        finding = self.check.run(make_ctx(code=code))
        assert finding is not None
        assert "PancakeSwap" in finding.description

    def test_interprets_recommendation(self):
        assert "Buy the DIP" in self.check.recommendation
