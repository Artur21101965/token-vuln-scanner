import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.reentrancy import ReentrancyCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.data import DataCollector
from src.rpc import RpcClient


def test_call_detected():
    data = Mock(spec=DataCollector)
    data.get_code.return_value = "0x60806040 .call( 60406080"
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = ReentrancyCheck()
    result = check.run(ctx)
    assert result is not None
    assert result.severity == Severity.MEDIUM


def test_no_call_detected():
    data = Mock(spec=DataCollector)
    data.get_code.return_value = "0x" + "00" * 500
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = ReentrancyCheck()
    result = check.run(ctx)
    assert result is None


def test_no_code_returns_none():
    data = Mock(spec=DataCollector)
    data.get_code.return_value = "0x"
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = ReentrancyCheck()
    result = check.run(ctx)
    assert result is None
