import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.access_control import AccessControlCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.data import DataCollector
from src.rpc import RpcClient


def test_access_control_detected():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = '[{"type":"function","name":"grantRole"},{"type":"function","name":"DEFAULT_ADMIN_ROLE"}]'
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = AccessControlCheck()
    result = check.run(ctx)
    assert result is not None
    assert result.severity == Severity.MEDIUM


def test_revoke_role_detected():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = '[{"type":"function","name":"revokeRole"}]'
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = AccessControlCheck()
    result = check.run(ctx)
    assert result is not None


def test_no_access_control():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = '[{"type":"function","name":"transfer"}]'
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = AccessControlCheck()
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
    check = AccessControlCheck()
    result = check.run(ctx)
    assert result is None
