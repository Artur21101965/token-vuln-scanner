import pytest
from unittest.mock import Mock, patch
from src.monitors.pool_monitor import PoolMonitor
from src.db.queue import TokenQueue
from src.rpc import RpcClient
from src.types import Chain


class TestPoolMonitor:
    def test_init(self):
        rpc = Mock(spec=RpcClient)
        q = Mock(spec=TokenQueue)
        m = PoolMonitor(rpc=rpc, chain=Chain.ETHEREUM, queue=q)
        assert m._chain == Chain.ETHEREUM
        assert m._queue is q

    def test_poll_no_factories(self):
        rpc = Mock(spec=RpcClient)
        q = Mock(spec=TokenQueue)
        m = PoolMonitor(rpc=rpc, chain=Chain.SOLANA, queue=q)
        assert m.poll() == 0

    def test_poll_returns_0_on_rpc_error(self):
        rpc = Mock(spec=RpcClient)
        rpc.get_block_number.side_effect = Exception("RPC error")
        q = Mock(spec=TokenQueue)
        m = PoolMonitor(rpc=rpc, chain=Chain.ETHEREUM, queue=q)
        assert m.poll() == 0

    def test_poll_advances_last_block(self):
        rpc = Mock(spec=RpcClient)
        rpc.get_block_number.return_value = 1000
        rpc.get_logs.return_value = []
        q = Mock(spec=TokenQueue)
        m = PoolMonitor(rpc=rpc, chain=Chain.ETHEREUM, queue=q)
        m.poll()
        assert m._last_block == 1000  # from_block 901, to_block 1000
