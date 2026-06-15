import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.lp_safety import LpNotBurnedCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.data import DataCollector
from src.rpc import RpcClient

BURN_ADDR = "0x000000000000000000000000000000000000dead"
BURN_DATA = "0" * 24 + BURN_ADDR[2:]

def test_lp_not_burned():
    rpc = Mock(spec=RpcClient)
    # totalSupply = 1000 (0x3e8), balanceOf(burn) = 0
    def side_effect(to, data, block="latest"):
        if "18160ddd" in data:  # totalSupply
            return "0x00000000000000000000000000000000000000000000000000000000000003e8"
        return "0x0000000000000000000000000000000000000000000000000000000000000000"
    rpc.eth_call.side_effect = side_effect
    ctx = CheckContext(
        token=TokenInfo(address="0xlp", symbol="LP", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )
    check = LpNotBurnedCheck()
    result = check.run(ctx)
    assert result is not None
    assert result.severity == Severity.HIGH
    assert "lp" in result.check_name

def test_lp_burned():
    rpc = Mock(spec=RpcClient)
    def side_effect(to, data, block="latest"):
        if "18160ddd" in data:
            return "0x00000000000000000000000000000000000000000000000000000000000003e8"
        return "0x" + BURN_DATA
    rpc.eth_call.side_effect = side_effect
    ctx = CheckContext(
        token=TokenInfo(address="0xlp", symbol="LP", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )
    check = LpNotBurnedCheck()
    result = check.run(ctx)
    assert result is None

def test_zero_supply_returns_none():
    rpc = Mock(spec=RpcClient)
    rpc.eth_call.return_value = "0x0000000000000000000000000000000000000000000000000000000000000000"
    ctx = CheckContext(
        token=TokenInfo(address="0xlp", symbol="LP", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )
    check = LpNotBurnedCheck()
    result = check.run(ctx)
    assert result is None

def test_lp_check_rpc_error_returns_none():
    rpc = Mock(spec=RpcClient)
    rpc.eth_call.side_effect = RuntimeError("RPC down")
    ctx = CheckContext(
        token=TokenInfo(address="0xlp", symbol="LP", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )
    check = LpNotBurnedCheck()
    result = check.run(ctx)
    assert result is None
