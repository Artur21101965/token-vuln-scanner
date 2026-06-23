from unittest.mock import Mock
from src.scanners.checks.evm.storage_layout import StorageLayoutCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain
from src.data import DataCollector
from src.rpc import RpcClient
from src.scanners.checks.evm.storage_layout import IMPLEMENTATION_SLOT, ADMIN_SLOT, TOTAL_SUPPLY_SLOT


def _make_ctx(rpc, dc=None) -> CheckContext:
    return CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
        data_collector=dc or Mock(spec=DataCollector),
        rpc=rpc,
    )


class TestStorageLayoutCheck:
    def test_name(self):
        check = StorageLayoutCheck()
        assert "storage" in check.name.lower()

    def test_no_anomalies_no_finding(self):
        rpc = Mock(spec=RpcClient)
        rpc.call.return_value = "0x" + "ff" * 32
        dc = Mock(spec=DataCollector)
        def get_code_side(addr):
            # 0xfff...fff is the impl/admin address — it has code
            if "fff" in addr.lower():
                return "0x" + "00" * 10
            return "0x"
        dc.get_code.side_effect = get_code_side
        check = StorageLayoutCheck()
        result = check.run(_make_ctx(rpc, dc))
        assert result is None

    def test_zero_implementation_detected(self):
        rpc = Mock(spec=RpcClient)
        def _side(*args):
            if args[1][1] == IMPLEMENTATION_SLOT:
                return "0x0000000000000000000000000000000000000000000000000000000000000000"
            return "0x" + "ff" * 32
        rpc.call.side_effect = _side
        dc = Mock(spec=DataCollector)
        check = StorageLayoutCheck()
        result = check.run(_make_ctx(rpc, dc))
        assert result is not None
        assert "implementation" in result.description.lower()

    def test_selfdestructed_impl_detected(self):
        rpc = Mock(spec=RpcClient)
        impl_addr = "0x0000000000000000000000000000000000000000000000000000000000000001"
        impl_slot_val = "0x0000000000000000000000000000000000000000000000000000000000000001"
        def _side(*args):
            if args[1][1] == IMPLEMENTATION_SLOT:
                return impl_slot_val
            return "0x" + "ff" * 32
        rpc.call.side_effect = _side
        dc = Mock(spec=DataCollector)
        dc.get_code.return_value = "0x"
        check = StorageLayoutCheck()
        result = check.run(_make_ctx(rpc, dc))
        assert result is not None
        assert "no code" in result.description.lower()

    def test_renounced_owner_detected(self):
        rpc = Mock(spec=RpcClient)
        dc = Mock(spec=DataCollector)
        def _side(*args):
            slot = args[1][1]
            if slot in ("0x0000000000000000000000000000000000000000000000000000000000000000",
                         "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",
                         "0x4e70b9e5e7fb8f82ed2f63081e2d8220ec0e54b18b0b4ee7056a8999b5f3b8d"):
                return "0x" + "00" * 32
            return "0x" + "ff" * 32
        rpc.call.side_effect = _side
        check = StorageLayoutCheck()
        result = check.run(_make_ctx(rpc, dc))
        assert result is not None
        assert "renounced" in result.description.lower()

    def test_zero_total_supply_detected(self):
        rpc = Mock(spec=RpcClient)
        dc = Mock(spec=DataCollector)
        def rpc_side(*args):
            if args[1][1] == TOTAL_SUPPLY_SLOT:
                return "0x" + "00" * 32
            return "0x" + "ff" * 32
        rpc.call.side_effect = rpc_side
        def get_code_side(addr):
            if "fff" in addr.lower():
                return "0x" + "00" * 10
            return "0x"
        dc.get_code.side_effect = get_code_side
        check = StorageLayoutCheck()
        result = check.run(_make_ctx(rpc, dc))
        assert result is not None
        assert "totalsupply" in result.description.lower()

    def test_rpc_error_no_finding(self):
        rpc = Mock(spec=RpcClient)
        rpc.call.side_effect = RuntimeError("rpc down")
        dc = Mock(spec=DataCollector)
        check = StorageLayoutCheck()
        result = check.run(_make_ctx(rpc, dc))
        assert result is None
