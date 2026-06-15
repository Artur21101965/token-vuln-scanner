import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.tax import HighTaxCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.data import DataCollector
from src.rpc import RpcClient


def test_tax_function_detected():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = '[{"type":"function","name":"sellTax","outputs":[{"type":"uint256"}]}]'
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = HighTaxCheck()
    result = check.run(ctx)
    assert result is not None
    assert result.severity == Severity.MEDIUM


def test_fee_function_detected():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = '[{"type":"function","name":"buyFee","outputs":[{"type":"uint256"}]}]'
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = HighTaxCheck()
    result = check.run(ctx)
    assert result is not None


def test_no_tax_function():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = '[{"type":"function","name":"transfer"}]'
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = HighTaxCheck()
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
    check = HighTaxCheck()
    result = check.run(ctx)
    assert result is None


def test_invalid_abi_returns_none():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = "not valid json"
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = HighTaxCheck()
    result = check.run(ctx)
    assert result is None
