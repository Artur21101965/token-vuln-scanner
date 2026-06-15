import pytest
from unittest.mock import Mock
from src.scanners.checks.solana.pool_ownership import PoolOwnershipCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain
from src.data import DataCollector
from src.rpc import RpcClient


def test_pool_ownership_check():
    ctx = CheckContext(
        token=TokenInfo(address="tokenaddr", symbol="T", chain=Chain.SOLANA),
        pool=PoolInfo(address="pooladdr", dex="Raydium", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=Mock(spec=RpcClient),
    )
    check = PoolOwnershipCheck()
    result = check.run(ctx)
    assert result is not None
