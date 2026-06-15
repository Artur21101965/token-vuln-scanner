import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.pausable import PausableCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.data import DataCollector
from src.rpc import RpcClient


def test_pause_selector_detected():
    data = Mock(spec=DataCollector)
    data.get_code.return_value = "0x" + "ff" * 100 + "8456cb59" + "00" * 100
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = PausableCheck()
    result = check.run(ctx)
    assert result is not None
    assert result.severity == Severity.MEDIUM


def test_pause_selector_3f4ba83a():
    data = Mock(spec=DataCollector)
    data.get_code.return_value = "0x" + "00" * 50 + "3f4ba83a" + "ff" * 50
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = PausableCheck()
    result = check.run(ctx)
    assert result is not None


def test_no_pause_selectors():
    data = Mock(spec=DataCollector)
    data.get_code.return_value = "0x" + "00" * 500
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = PausableCheck()
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
    check = PausableCheck()
    result = check.run(ctx)
    assert result is None
