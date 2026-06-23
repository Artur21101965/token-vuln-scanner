import pytest
from unittest.mock import Mock, patch
from src.scanners.checks.evm.bytecode_selfdestruct import BytecodeSelfdestructCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Finding, Severity, Chain
from src.data import DataCollector
from src.rpc import RpcClient


SELFDESTRUCT_NO_GUARD = "0x60006000ff"  # PUSH1 0, PUSH1 0, SELFDESTRUCT


def _make_ctx(bytecode_hex: str) -> CheckContext:
    dc = Mock(spec=DataCollector)
    dc.get_code.return_value = bytecode_hex
    rpc = Mock(spec=RpcClient)
    return CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
        data_collector=dc,
        rpc=rpc,
    )


class TestBytecodeSelfdestructCheck:
    def test_name(self):
        check = BytecodeSelfdestructCheck()
        assert "selfdestruct" in check.name.lower()

    def test_selfdestruct_no_guard_detected(self):
        check = BytecodeSelfdestructCheck()
        ctx = _make_ctx(SELFDESTRUCT_NO_GUARD)
        result = check.run(ctx)
        assert result is not None
        assert result.severity == Severity.CRITICAL
        assert "SELFDESTRUCT" in result.description

    def test_no_selfdestruct_no_finding(self):
        check = BytecodeSelfdestructCheck()
        ctx = _make_ctx("0x6001600201")  # PUSH1 1, PUSH1 2, ADD, STOP
        result = check.run(ctx)
        assert result is None

    def test_selfdestruct_with_caller_guard_no_finding(self):
        # CALLER, PUSH20 0xdead, EQ, PUSH1 0x19, JUMPI, ..., SELFDESTRUCT
        bytecode = (
            "33"                    # CALLER
            "73dead000000000000000000000000000000000000"  # PUSH20 0xdead
            "14"                    # EQ
            "6019"                  # PUSH1 0x19
            "57"                    # JUMPI
            "60006000ff"            # PUSH1 0, PUSH1 0, SELFDESTRUCT
        )
        check = BytecodeSelfdestructCheck()
        ctx = _make_ctx("0x" + bytecode)
        result = check.run(ctx)
        assert result is None

    def test_empty_bytecode_no_finding(self):
        check = BytecodeSelfdestructCheck()
        ctx = _make_ctx("0x")
        result = check.run(ctx)
        assert result is None

    def test_get_code_error_no_finding(self):
        dc = Mock(spec=DataCollector)
        dc.get_code.side_effect = RuntimeError("RPC error")
        ctx = CheckContext(
            token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
            pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
            data_collector=dc,
            rpc=Mock(spec=RpcClient),
        )
        check = BytecodeSelfdestructCheck()
        result = check.run(ctx)
        assert result is None
