from unittest.mock import Mock, patch
from src.scanners.checks.evm.sandwich_flash import SandwichFlashCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain
from src.data import DataCollector
from src.rpc import RpcClient

SWAP_TOPIC = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"
FAKE_POOLS = {"pairs": [{"pairAddress": "0xpool1", "dexId": "uniswap", "chainId": "ethereum"}]}


def _make_ctx(rpc, dc=None) -> CheckContext:
    return CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
        data_collector=dc or Mock(spec=DataCollector),
        rpc=rpc,
    )


class TestSandwichFlashCheck:
    def test_name(self):
        check = SandwichFlashCheck()
        assert "sandwich" in check.name.lower()

    def test_no_pools_no_finding(self):
        rpc = Mock(spec=RpcClient)
        check = SandwichFlashCheck()
        with patch("src.scanners.checks.evm.sandwich_flash.httpx.get") as mock_get:
            mock_get.return_value = Mock(status_code=200)
            mock_get.return_value.json.return_value = {"pairs": []}
            result = check.run(_make_ctx(rpc))
            assert result is None

    def test_no_swap_events_no_finding(self):
        rpc = Mock(spec=RpcClient)
        side_effects = [
            "0x1000000",  # swap blockNumber
            [],           # swap getLogs (empty)
            "0x1000000",  # flash blockNumber
        ]
        side_effects.extend([[]] * 7)  # 7 providers all return empty
        rpc.call.side_effect = side_effects
        check = SandwichFlashCheck()
        with patch("src.scanners.checks.evm.sandwich_flash.httpx.get") as mock_get:
            mock_get.return_value = Mock(status_code=200)
            mock_get.return_value.json.return_value = FAKE_POOLS
            result = check.run(_make_ctx(rpc))
            assert result is None

    def test_sandwich_detected(self):
        rpc = Mock(spec=RpcClient)
        addr1 = "0x" + "0" * 24 + "dead000000000000000000000000000000000001"
        addr2 = "0x" + "0" * 24 + "dead000000000000000000000000000000000002"
        # swap: blockNumber + getLogs(2 events) = 2 calls
        # flash: blockNumber + 7 providers (all return []) = 8 calls
        side_effects = [
            "0x1000000",
            [
                {"blockNumber": "0x123456", "topics": [SWAP_TOPIC, addr1, addr2]},
                {"blockNumber": "0x123456", "topics": [SWAP_TOPIC, addr2, addr1]},
            ],
            "0x1000000",
        ]
        side_effects.extend([[]] * 7)
        rpc.call.side_effect = side_effects
        check = SandwichFlashCheck()
        with patch("src.scanners.checks.evm.sandwich_flash.httpx.get") as mock_get:
            mock_get.return_value = Mock(status_code=200)
            mock_get.return_value.json.return_value = FAKE_POOLS
            result = check.run(_make_ctx(rpc))
            assert result is not None
            assert "sandwich" in result.description.lower()

    def test_flash_loan_detected(self):
        rpc = Mock(spec=RpcClient)
        # swap: blockNumber + getLogs(empty) = 2 calls
        # flash: blockNumber + 1st provider returns [data] + 6 more providers return []
        side_effects = [
            "0x1000000",  # swap blockNumber
            [],           # swap getLogs (empty)
            "0x1000000",  # flash blockNumber
            [{"transactionHash": "0xtx1"}],  # 1st provider matches
        ]
        side_effects.extend([[]] * 6)  # remaining 6 providers return empty
        rpc.call.side_effect = side_effects
        check = SandwichFlashCheck()
        with patch("src.scanners.checks.evm.sandwich_flash.httpx.get") as mock_get:
            mock_get.return_value = Mock(status_code=200)
            mock_get.return_value.json.return_value = FAKE_POOLS
            result = check.run(_make_ctx(rpc))
            assert result is not None
            assert "flash" in result.description.lower()

    def test_rpc_error_no_finding(self):
        rpc = Mock(spec=RpcClient)
        rpc.call.side_effect = RuntimeError("rpc down")
        check = SandwichFlashCheck()
        with patch("src.scanners.checks.evm.sandwich_flash.httpx.get") as mock_get:
            mock_get.return_value = Mock(status_code=200)
            mock_get.return_value.json.return_value = FAKE_POOLS
            result = check.run(_make_ctx(rpc))
            assert result is None
