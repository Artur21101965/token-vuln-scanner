import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.hidden import HiddenSelfdestructCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.data import DataCollector
from src.rpc import RpcClient


def test_selfdestruct_in_code():
    data = Mock(spec=DataCollector)
    data.get_code.return_value = "0x60806040selfdestruct60406080"
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = HiddenSelfdestructCheck()
    result = check.run(ctx)
    assert result is not None
    assert result.severity == Severity.CRITICAL


def test_no_selfdestruct():
    data = Mock(spec=DataCollector)
    data.get_code.return_value = "0x" + "00" * 500
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = HiddenSelfdestructCheck()
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
    check = HiddenSelfdestructCheck()
    result = check.run(ctx)
    assert result is None
