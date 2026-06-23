from unittest.mock import Mock, patch
from src.scanners.checks.evm.cross_contract import CrossContractCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain
from src.data import DataCollector
from src.rpc import RpcClient

FAKE_POOLS_RESPONSE = {
    "pairs": [
        {
            "chainId": "ethereum",
            "dexId": "uniswap",
            "pairAddress": "0xpool1",
            "baseToken": {"address": "0xtoken"},
        },
    ]
}

EMPTY_RESPONSE = {"pairs": []}


class TestCrossContractCheck:
    def test_name(self):
        check = CrossContractCheck()
        assert "cross" in check.name.lower()

    def test_no_pools_no_finding(self):
        check = CrossContractCheck()
        dc = Mock(spec=DataCollector)
        ctx = CheckContext(
            token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
            pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
            data_collector=dc,
            rpc=Mock(spec=RpcClient),
        )
        with patch("src.scanners.checks.evm.cross_contract.httpx.get") as mock_get:
            mock_get.return_value = Mock(status_code=200)
            mock_get.return_value.json.return_value = EMPTY_RESPONSE
            result = check.run(ctx)
            assert result is None

    def test_pool_with_drain_functions(self):
        check = CrossContractCheck()
        dc = Mock(spec=DataCollector)
        # PUSH4 with selector f4c5c2de (sweep), then STOP
        dc.get_code.return_value = "0x63f4c5c2de00"
        ctx = CheckContext(
            token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
            pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
            data_collector=dc,
            rpc=Mock(spec=RpcClient),
        )
        with patch("src.scanners.checks.evm.cross_contract.httpx.get") as mock_get:
            mock_get.return_value = Mock(status_code=200)
            mock_get.return_value.json.return_value = FAKE_POOLS_RESPONSE
            result = check.run(ctx)
            assert result is not None
            assert "sweep" in result.description.lower()

    def test_clean_pool_no_finding(self):
        check = CrossContractCheck()
        dc = Mock(spec=DataCollector)
        dc.get_code.return_value = "0x00"  # just STOP
        ctx = CheckContext(
            token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
            pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
            data_collector=dc,
            rpc=Mock(spec=RpcClient),
        )
        with patch("src.scanners.checks.evm.cross_contract.httpx.get") as mock_get:
            mock_get.return_value = Mock(status_code=200)
            mock_get.return_value.json.return_value = FAKE_POOLS_RESPONSE
            result = check.run(ctx)
            assert result is None
