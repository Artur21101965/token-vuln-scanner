import pytest
from unittest.mock import Mock
import struct, base64
from src.scanners.checks.solana.authorities import MintAuthorityCheck, FreezeAuthorityCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain
from src.data import DataCollector
from src.rpc import RpcClient


def _mint_account(mint_auth: bool = True, freeze_auth: bool = True) -> str:
    """Build base64 Solana mint account (82-byte SPL Token format)."""
    mint_opt = struct.pack("<I", 1) + b'\x11' * 32 if mint_auth else struct.pack("<I", 0) + b'\x00' * 32
    supply = struct.pack("<Q", 1_000_000)
    decimals = struct.pack("B", 9)
    is_init = struct.pack("B", 1)
    freeze_opt = struct.pack("<I", 1) + b'\x22' * 32 if freeze_auth else struct.pack("<I", 0) + b'\x00' * 32
    return base64.b64encode(mint_opt + supply + decimals + is_init + freeze_opt).decode()


@pytest.fixture
def solana_ctx():
    return CheckContext(
        token=TokenInfo(address="tokenaddr", symbol="T", chain=Chain.SOLANA),
        pool=PoolInfo(address="pooladdr", dex="Raydium", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=Mock(spec=RpcClient),
    )


def test_mint_authority_detected(solana_ctx):
    solana_ctx.rpc.call.return_value = {
        "result": {"value": {"data": [_mint_account(mint_auth=True), "base64"]}}
    }
    check = MintAuthorityCheck()
    result = check.run(solana_ctx)
    assert result is not None
    assert "mint" in result.check_name
    assert result.details.get("mint_authority") == "11" * 32


def test_mint_authority_revoked(solana_ctx):
    solana_ctx.rpc.call.return_value = {
        "result": {"value": {"data": [_mint_account(mint_auth=False), "base64"]}}
    }
    check = MintAuthorityCheck()
    result = check.run(solana_ctx)
    assert result is None


def test_freeze_authority_detected(solana_ctx):
    solana_ctx.rpc.call.return_value = {
        "result": {"value": {"data": [_mint_account(freeze_auth=True), "base64"]}}
    }
    check = FreezeAuthorityCheck()
    result = check.run(solana_ctx)
    assert result is not None
    assert "freeze" in result.check_name
    assert result.details.get("freeze_authority") == "22" * 32


def test_freeze_authority_revoked(solana_ctx):
    solana_ctx.rpc.call.return_value = {
        "result": {"value": {"data": [_mint_account(freeze_auth=False), "base64"]}}
    }
    check = FreezeAuthorityCheck()
    result = check.run(solana_ctx)
    assert result is None
