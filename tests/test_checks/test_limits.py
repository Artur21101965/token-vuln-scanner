import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.limits import MaxTxLimitCheck, MaxWalletLimitCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.data import DataCollector
from src.rpc import RpcClient


def test_max_tx_detected():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = '[{"type":"function","name":"maxTxAmount"}]'
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = MaxTxLimitCheck()
    result = check.run(ctx)
    assert result is not None
    assert result.severity == Severity.LOW


def test_max_tx_not_found():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = '[{"type":"function","name":"transfer"}]'
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = MaxTxLimitCheck()
    result = check.run(ctx)
    assert result is None


def test_max_wallet_detected():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = '[{"type":"function","name":"maxWalletAmount"}]'
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = MaxWalletLimitCheck()
    result = check.run(ctx)
    assert result is not None
    assert result.severity == Severity.LOW


def test_max_wallet_not_found():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = '[{"type":"function","name":"transfer"}]'
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = MaxWalletLimitCheck()
    result = check.run(ctx)
    assert result is None


def test_no_abi_returns_none():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = None
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = MaxTxLimitCheck()
    result = check.run(ctx)
    assert result is None
