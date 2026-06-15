import pytest
from unittest.mock import Mock
from src.scanners.checks.solana.authorities import MintAuthorityCheck, FreezeAuthorityCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain
from src.data import DataCollector
from src.rpc import RpcClient


@pytest.fixture
def solana_ctx():
    return CheckContext(
        token=TokenInfo(address="tokenaddr", symbol="T", chain=Chain.SOLANA),
        pool=PoolInfo(address="pooladdr", dex="Raydium", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=Mock(spec=RpcClient),
    )


def test_mint_authority_check(solana_ctx):
    check = MintAuthorityCheck()
    result = check.run(solana_ctx)
    assert result is not None
    assert "mint" in result.check_name


def test_freeze_authority_check(solana_ctx):
    check = FreezeAuthorityCheck()
    result = check.run(solana_ctx)
    assert result is not None
    assert "freeze" in result.check_name
