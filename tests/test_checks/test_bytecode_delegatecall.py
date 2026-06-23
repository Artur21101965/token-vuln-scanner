import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.bytecode_delegatecall import BytecodeDelegatecallCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Severity, Chain
from src.data import DataCollector
from src.rpc import RpcClient


def _make_ctx(bytecode_hex: str) -> CheckContext:
    dc = Mock(spec=DataCollector)
    dc.get_code.return_value = bytecode_hex
    return CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
        data_collector=dc,
        rpc=Mock(spec=RpcClient),
    )


class TestBytecodeDelegatecallCheck:
    def test_name(self):
        check = BytecodeDelegatecallCheck()
        assert "delegatecall" in check.name.lower()

    def test_no_delegatecall_no_finding(self):
        check = BytecodeDelegatecallCheck()
        ctx = _make_ctx("0x6001600201")
        assert check.run(ctx) is None

    def test_delegatecall_from_calldata_detected(self):
        # CALLDATALOAD 0, ..., DELEGATECALL
        bytecode = "0x" + "35" + "00" * 30 + "f4"
        check = BytecodeDelegatecallCheck()
        ctx = _make_ctx(bytecode)
        result = check.run(ctx)
        assert result is not None
        assert result.severity == Severity.HIGH
        assert "DELEGATECALL" in result.description

    def test_delegatecall_hardcoded_no_finding(self):
        # PUSH20 0xdead..., DELEGATECALL (hardcoded target is fine)
        bytecode = "0x" + "73" + "dead000000000000000000000000000000000000" + "f4"
        check = BytecodeDelegatecallCheck()
        ctx = _make_ctx(bytecode)
        result = check.run(ctx)
        assert result is None

    def test_empty_bytecode_no_finding(self):
        check = BytecodeDelegatecallCheck()
        assert check.run(_make_ctx("0x")) is None
