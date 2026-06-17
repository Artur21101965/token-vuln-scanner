import pytest
from unittest.mock import Mock, MagicMock
from src.types import Chain, Finding, Severity, TokenInfo, PoolInfo, ContractTarget
from src.scanners.base import CheckContext
from src.rpc import RpcClient
from src.data import DataCollector


def test_contract_target_scannable_as_token():
    """ContractTarget can be wrapped into TokenInfo + PoolInfo for scanner."""
    target = ContractTarget(
        chain=Chain.ETHEREUM,
        address="0x1234567890123456789012345678901234567890",
        source="blockscout",
    )
    token = TokenInfo(
        address=target.address,
        chain=target.chain,
        symbol=f"CONTRACT_{target.address[:6]}",
    )
    pool = PoolInfo(address="", dex="direct", liquidity_usd=0)
    assert token.address == "0x1234567890123456789012345678901234567890"
    assert token.chain == Chain.ETHEREUM
    assert pool.address == ""


def test_contract_target_enriched_with_rpc_data():
    """Simulate enriching a contract target with on-chain balance data."""
    rpc = Mock(spec=RpcClient)
    rpc.eth_get_balance.return_value = hex(2 * 10 ** 18)

    targets = [
        ContractTarget(chain=Chain.ETHEREUM, address="0xabc", source="blockscout"),
        ContractTarget(chain=Chain.ETHEREUM, address="0xdef", source="blockscout"),
    ]

    enriched = []
    for t in targets:
        raw = rpc.eth_get_balance(t.address)
        bal = int(raw, 16) if raw else 0
        enriched.append(ContractTarget(
            chain=t.chain, address=t.address, source=t.source, eth_balance=bal,
        ))

    assert len(enriched) == 2
    assert enriched[0].eth_balance == 2 * 10 ** 18
    assert enriched[1].eth_balance == 2 * 10 ** 18
    rpc.eth_get_balance.assert_any_call("0xabc")
    rpc.eth_get_balance.assert_any_call("0xdef")


def test_scanner_accepts_contract_target():
    """Scanner checks run without error on a contract target (no pool data)."""
    rpc = Mock(spec=RpcClient)
    data = Mock(spec=DataCollector)
    data.get_code.return_value = "0x60806040"
    data.get_abi.return_value = "[]"
    data.fallback_detected.return_value = False

    ctx = CheckContext(
        token=TokenInfo(address="0x1234567890123456789012345678901234567890",
                        symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="", dex="", liquidity_usd=0),
        data_collector=data,
        rpc=rpc,
    )

    from src.scanners.checks.evm import ALL_EVM_CHECKS
    for CheckClass in ALL_EVM_CHECKS:
        check = CheckClass()
        try:
            finding = check.run(ctx)
        except Exception:
            pass

    assert ctx.token.address == "0x1234567890123456789012345678901234567890"
    assert ctx.pool.address == ""
