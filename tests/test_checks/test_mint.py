import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.mint import MintCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.data import DataCollector
from src.rpc import RpcClient


def test_mint_in_abi_found():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = '''
    [{"type":"function","name":"mint","inputs":[{"type":"uint256"}],"stateMutability":"nonpayable"}]
    '''
    data.get_code.return_value = "0x60806040"
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = MintCheck()
    result = check.run(ctx)
    assert result is not None
    assert result.severity == Severity.CRITICAL


def test_mint_selector_in_bytecode():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = None
    data.get_code.return_value = "0x" + "00" * 100 + "1249c58b" + "ff" * 100
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = MintCheck()
    result = check.run(ctx)
    assert result is not None


def test_no_mint_function():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = None
    data.get_code.return_value = "0x" + "00" * 300
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = MintCheck()
    result = check.run(ctx)
    assert result is None


def test_no_code_returns_none():
    data = Mock(spec=DataCollector)
    data.get_abi.return_value = None
    data.get_code.return_value = "0x"
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=data,
        rpc=Mock(spec=RpcClient),
    )
    check = MintCheck()
    result = check.run(ctx)
    assert result is None
