from unittest.mock import Mock
from src.scanners.checks.evm.bytecode_sstore import BytecodeSstoreCheck
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


class TestBytecodeSstoreCheck:
    def test_name(self):
        check = BytecodeSstoreCheck()
        assert "sstore" in check.name.lower()

    def test_sstore_no_caller_check_detected(self):
        check = BytecodeSstoreCheck()
        ctx = _make_ctx("0x6000600055")  # PUSH1 0, PUSH1 0, SSTORE
        result = check.run(ctx)
        assert result is not None
        assert "SSTORE" in result.description

    def test_no_sstore_no_finding(self):
        check = BytecodeSstoreCheck()
        ctx = _make_ctx("0x6001600201")  # PUSH1 1, PUSH1 2, ADD, STOP
        assert check.run(ctx) is None

    def test_sstore_with_caller_guard_no_finding(self):
        bytecode = "0x" + "33" + "00" * 5 + "6000600055"  # CALLER then SSTORE
        check = BytecodeSstoreCheck()
        ctx = _make_ctx(bytecode)
        assert check.run(ctx) is None

    def test_empty_bytecode_no_finding(self):
        check = BytecodeSstoreCheck()
        assert check.run(_make_ctx("0x")) is None
