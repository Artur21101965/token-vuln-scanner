import pytest
from unittest.mock import Mock
import struct, base64
from src.scanners.checks.solana.pool_ownership import PoolOwnershipCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain
from src.data import DataCollector
from src.rpc import RpcClient


def _pool_account(owner_set: bool = True) -> str:
    """Build a mock Raydium AMM pool account with owner at offset 216."""
    data = bytearray(248)
    data[0:1] = b'\x01'  # version
    if owner_set:
        data[216:248] = b'\x33' * 32  # owner key
    return base64.b64encode(bytes(data)).decode()


def test_pool_ownership_detected():
    ctx = CheckContext(
        token=TokenInfo(address="tokenaddr", symbol="T", chain=Chain.SOLANA),
        pool=PoolInfo(address="pooladdr", dex="Raydium", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=Mock(spec=RpcClient),
    )
    ctx.rpc.call.return_value = {
        "result": {"value": {"data": [_pool_account(owner_set=True), "base64"]}}
    }
    check = PoolOwnershipCheck()
    result = check.run(ctx)
    assert result is not None
    assert "pool_owner" in result.details
    assert result.details["pool_owner"] == "33" * 32


def test_pool_ownership_renounced():
    ctx = CheckContext(
        token=TokenInfo(address="tokenaddr", symbol="T", chain=Chain.SOLANA),
        pool=PoolInfo(address="pooladdr", dex="Raydium", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=Mock(spec=RpcClient),
    )
    ctx.rpc.call.return_value = {
        "result": {"value": {"data": [_pool_account(owner_set=False), "base64"]}}
    }
    check = PoolOwnershipCheck()
    result = check.run(ctx)
    assert result is None
