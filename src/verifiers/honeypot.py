from typing import Optional
from src.verifiers.base import Verifier, VerificationResult
from src.types import Finding, Severity, Chain
from src.scanners.base import CheckContext

CHAIN_ROUTERS: dict[Chain, dict[str, str]] = {
    Chain.ETHEREUM: {
        "router": "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
        "weth": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    },
    Chain.BSC: {
        "router": "0x10ED43C718714eb63d5aA57B78B54704E256024E",
        "weth": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
    },
    Chain.POLYGON: {
        "router": "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff",
        "weth": "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
    },
    Chain.ARBITRUM: {
        "router": "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24",
        "weth": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
    },
    Chain.BASE: {
        "router": "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24",
        "weth": "0x4200000000000000000000000000000000000006",
    },
    Chain.OPTIMISM: {
        "router": "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24",
        "weth": "0x4200000000000000000000000000000000000006",
    },
    Chain.AVALANCHE: {
        "router": "0x60aE616a2155Ee3d9A68541Ba4544862310933d4",
        "weth": "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7",
    },
    Chain.ZKSYNC: {
        "router": "0xB3e808e102acEbe8B9d6B4eF0c7fEb3B7bC9D1C3",
        "weth": "0x5AEa5775959fBC2557F878E60aBcbf8A0bE931E6",
    },
    Chain.LINEA: {
        "router": "0x8cFe327CEc66d1C090Dd72bd0FF11d690C33a2Eb",
        "weth": "0xe5D7C2a44FfDDf6b295A15c148167daaAf5Cf34f",
    },
    Chain.SCROLL: {
        "router": "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24",
        "weth": "0x5300000000000000000000000000000000000004",
    },
}

SWAP_ETH_FOR_TOKENS_SIG = "0x7ff36ab5"
CALLER = "0x0000000000000000000000000000000000000001"
BUY_AMOUNT_WEI = 10 ** 17  # 0.1 ETH


def _encode_buy(weth: str, token: str) -> str:
    deadline = "f" * 64
    return (SWAP_ETH_FOR_TOKENS_SIG +
            "0000000000000000000000000000000000000000000000000000000000000000" +
            "0000000000000000000000000000000000000000000000000000000000000080" +
            CALLER[2:].zfill(64) +
            deadline +
            "0000000000000000000000000000000000000000000000000000000000000002" +
            weth[2:].zfill(64) +
            token[2:].zfill(64))


def _parse_swap_result(result: str) -> int:
    if not result or len(result) < 66:
        return 0
    raw = result[2:]
    if len(raw) < 192:
        return 0
    return int(raw[192:256], 16)


class HoneypotVerifier(Verifier):
    @property
    def name(self) -> str:
        return "honeypot_simulator"

    def can_verify(self, finding: Finding) -> bool:
        return finding.check_name == "potential_honeypot"

    def verify(self, ctx: CheckContext, finding: Finding) -> VerificationResult:
        if not ctx.pool.address:
            return VerificationResult(
                finding=finding,
                confirmed=False,
                confidence=0.0,
                evidence="No pair address — cannot simulate, dismissing",
            )

        routers = CHAIN_ROUTERS.get(ctx.token.chain)
        if not routers:
            return VerificationResult(
                finding=finding,
                confirmed=False,
                confidence=0.0,
                evidence=f"No router configured for {ctx.token.chain.name} — dismissing",
            )

        router_addr = routers["router"]
        weth_addr = routers["weth"]
        token_addr = ctx.token.address

        buy_data = _encode_buy(weth_addr, token_addr)
        value_hex = hex(BUY_AMOUNT_WEI)

        try:
            buy_result = ctx.rpc.eth_call(
                router_addr, buy_data,
                from_address=CALLER,
                value=value_hex,
            )
        except Exception as exc:
            return VerificationResult(
                finding=finding,
                confirmed=True,
                confidence=0.95,
                evidence=f"Buy simulation reverted on {ctx.token.chain.name}: {exc}",
            )

        amount_bought = _parse_swap_result(buy_result)
        if amount_bought == 0:
            return VerificationResult(
                finding=finding,
                confirmed=True,
                confidence=0.9,
                evidence=f"Bought 0 tokens on {ctx.token.chain.name} — 100% tax or fake liquidity",
            )

        effective_tax_pct = (1 - amount_bought / BUY_AMOUNT_WEI) * 100
        if effective_tax_pct > 20:
            return VerificationResult(
                finding=finding,
                confirmed=True,
                confidence=0.8,
                evidence=f"Buy OK but only got {amount_bought} tokens ({effective_tax_pct:.0f}% tax) on {ctx.token.chain.name}",
            )

        return VerificationResult(
            finding=finding,
            confirmed=False,
            confidence=0.7,
            evidence=f"Buy OK ({amount_bought} tokens, {effective_tax_pct:.1f}% tax) on {ctx.token.chain.name} — not a honeypot",
        )
