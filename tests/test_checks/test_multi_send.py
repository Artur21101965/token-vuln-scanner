import pytest
from unittest.mock import Mock, patch
from src.scanners.checks.evm.multi_send import MultiSendCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.data import DataCollector
from src.rpc import RpcClient


def make_ctx(rpc=None):
    return CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=1000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc or Mock(spec=RpcClient),
    )


class TestMultiSendCheck:
    check = MultiSendCheck()

    def test_name_and_severity(self):
        assert self.check.name == "multi_send_detected"
        assert self.check.severity == Severity.HIGH

    def test_returns_none_on_rpc_error(self):
        rpc = Mock(spec=RpcClient)
        rpc.get_block_number.side_effect = Exception("RPC error")
        assert self.check.run(make_ctx(rpc=rpc)) is None

    def test_returns_none_when_no_logs(self):
        rpc = Mock(spec=RpcClient)
        rpc.get_block_number.return_value = 1000
        rpc.get_logs.return_value = []
        assert self.check.run(make_ctx(rpc=rpc)) is None

    def test_returns_none_for_few_transfers(self):
        rpc = Mock(spec=RpcClient)
        rpc.get_block_number.return_value = 1000
        rpc.get_logs.return_value = [
            {"transactionHash": "0xa", "topics": ["0x...", "0x...", "0xto1"]},
            {"transactionHash": "0xa", "topics": ["0x...", "0x...", "0xto2"]},
        ]
        assert self.check.run(make_ctx(rpc=rpc)) is None

    def test_detects_multi_send(self):
        rpc = Mock(spec=RpcClient)
        rpc.get_block_number.return_value = 1000
        transfers = []
        for i in range(60):
            transfers.append({
                "transactionHash": "0xmulti",
                "topics": ["0x...", "0x...", f"0x{i:040x}"],
            })
        rpc.get_logs.return_value = transfers

        finding = self.check.run(make_ctx(rpc=rpc))
        assert finding is not None
        assert "60" in finding.description

    def test_returns_none_for_solana(self):
        ctx = CheckContext(
            token=TokenInfo(address="soladdr", symbol="S", chain=Chain.SOLANA),
            pool=PoolInfo(address="pool", dex="Raydium", liquidity_usd=1000),
            data_collector=Mock(spec=DataCollector),
            rpc=Mock(spec=RpcClient),
        )
        assert self.check.run(ctx) is None
