from unittest.mock import Mock
from src.scanners.checks.evm.historical import HistoricalAnalysisCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain
from src.data import DataCollector
from src.rpc import RpcClient

MINT_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
ZERO_ADDR_PADDED = "0x0000000000000000000000000000000000000000000000000000000000000000"
SOME_ADDR = "0x000000000000000000000000abc0000000000000000000000000000000000000"


def _make_ctx(rpc: RpcClient) -> CheckContext:
    return CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )


class TestHistoricalAnalysisCheck:
    def test_name(self):
        check = HistoricalAnalysisCheck()
        assert "historical" in check.name.lower()

    def test_no_events_no_finding(self):
        rpc = Mock(spec=RpcClient)
        rpc.call.side_effect = [
            "0x1000000",  # blockNumber
            [],  # getLogs returns empty
            [],
            [],
        ]
        check = HistoricalAnalysisCheck()
        result = check.run(_make_ctx(rpc))
        assert result is None

    def test_many_mint_events_detected(self):
        rpc = Mock(spec=RpcClient)
        rpc.call.side_effect = [
            "0x1000000",  # eth_blockNumber for transfer
            [             # eth_getLogs for transfer
                {"topics": [MINT_TRANSFER_TOPIC, ZERO_ADDR_PADDED, SOME_ADDR]},
                {"topics": [MINT_TRANSFER_TOPIC, ZERO_ADDR_PADDED, SOME_ADDR]},
                {"topics": [MINT_TRANSFER_TOPIC, ZERO_ADDR_PADDED, SOME_ADDR]},
                {"topics": [MINT_TRANSFER_TOPIC, ZERO_ADDR_PADDED, SOME_ADDR]},
                {"topics": [MINT_TRANSFER_TOPIC, ZERO_ADDR_PADDED, SOME_ADDR]},
                {"topics": [MINT_TRANSFER_TOPIC, ZERO_ADDR_PADDED, SOME_ADDR]},
                {"topics": [MINT_TRANSFER_TOPIC, ZERO_ADDR_PADDED, SOME_ADDR]},
                {"topics": [MINT_TRANSFER_TOPIC, ZERO_ADDR_PADDED, SOME_ADDR]},
                {"topics": [MINT_TRANSFER_TOPIC, ZERO_ADDR_PADDED, SOME_ADDR]},
                {"topics": [MINT_TRANSFER_TOPIC, ZERO_ADDR_PADDED, SOME_ADDR]},
                {"topics": [MINT_TRANSFER_TOPIC, ZERO_ADDR_PADDED, SOME_ADDR]},
            ],
            "0x1000000",  # eth_blockNumber for ownership
            [],           # eth_getLogs for ownership
            "0x1000000",  # eth_blockNumber for upgrade
            [],           # eth_getLogs for upgrade
        ]
        check = HistoricalAnalysisCheck()
        result = check.run(_make_ctx(rpc))
        assert result is not None
        assert "mint" in result.description.lower()

    def test_many_ownership_changes_detected(self):
        rpc = Mock(spec=RpcClient)
        rpc.call.side_effect = [
            "0x1000000",  # eth_blockNumber for transfer
            [],           # eth_getLogs for transfer
            "0x1000000",  # eth_blockNumber for ownership
            [             # eth_getLogs for ownership
                {"topics": ["0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0"]},
                {"topics": ["0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0"]},
                {"topics": ["0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0"]},
                {"topics": ["0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0"]},
            ],
            "0x1000000",  # eth_blockNumber for upgrade
            [],           # eth_getLogs for upgrade
        ]
        check = HistoricalAnalysisCheck()
        result = check.run(_make_ctx(rpc))
        assert result is not None
        assert "ownership" in result.description.lower()

    def test_upgrade_events_detected(self):
        rpc = Mock(spec=RpcClient)
        rpc.call.side_effect = [
            "0x1000000",  # eth_blockNumber for transfer
            [],           # eth_getLogs for transfer
            "0x1000000",  # eth_blockNumber for ownership
            [],           # eth_getLogs for ownership
            "0x1000000",  # eth_blockNumber for upgrade
            [             # eth_getLogs for upgrade
                {"topics": ["0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"]},
            ],
        ]
        check = HistoricalAnalysisCheck()
        result = check.run(_make_ctx(rpc))
        assert result is not None
        assert "upgrade" in result.description.lower()

    def test_rpc_error_no_finding(self):
        rpc = Mock(spec=RpcClient)
        rpc.call.side_effect = RuntimeError("connection failed")
        check = HistoricalAnalysisCheck()
        result = check.run(_make_ctx(rpc))
        assert result is None
