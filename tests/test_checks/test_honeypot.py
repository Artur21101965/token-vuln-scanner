import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.honeypot import HoneypotCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain
from src.data import DataCollector
from src.rpc import RpcClient

def test_honeypot_always_flags_for_manual_review():
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=Mock(spec=RpcClient),
    )
    check = HoneypotCheck()
    result = check.run(ctx)
    assert result is not None
    assert result.severity.name == "CRITICAL"
    assert "manual review" in result.description.lower()
