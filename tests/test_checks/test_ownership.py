import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.ownership import OwnerNotRenouncedCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.data import DataCollector
from src.rpc import RpcClient


def test_owner_not_renounced_finding():
    rpc = Mock(spec=RpcClient)
    rpc.eth_call.return_value = "0x0000000000000000000000001234567890abcdef1234567890abcdef12345678"
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )
    check = OwnerNotRenouncedCheck()
    result = check.run(ctx)
    assert result is not None
    assert result.severity == Severity.HIGH
    assert "not renounced" in result.description.lower()


def test_owner_renounced_no_finding():
    rpc = Mock(spec=RpcClient)
    rpc.eth_call.return_value = "0x0000000000000000000000000000000000000000000000000000000000000000"
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )
    check = OwnerNotRenouncedCheck()
    result = check.run(ctx)
    assert result is None


def test_burn_address_no_finding():
    rpc = Mock(spec=RpcClient)
    burn_addr = "0x000000000000000000000000000000000000dead"
    rpc.eth_call.return_value = "0x" + "0" * 24 + burn_addr[2:]
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )
    check = OwnerNotRenouncedCheck()
    result = check.run(ctx)
    assert result is None


def test_rpc_exception_returns_none():
    rpc = Mock(spec=RpcClient)
    rpc.eth_call.side_effect = Exception("RPC error")
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )
    check = OwnerNotRenouncedCheck()
    result = check.run(ctx)
    assert result is None
