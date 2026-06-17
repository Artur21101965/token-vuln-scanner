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

GET_AMOUNTS_OUT_SIG = "0xd06ca61f"


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

        try:
            path = [weth_addr, ctx.token.address, weth_addr]
            amount = 10 ** 18
            data = (GET_AMOUNTS_OUT_SIG +
                    hex(amount)[2:].zfill(64) +
                    "0000000000000000000000000000000000000000000000000000000000000060"
                    "0000000000000000000000000000000000000000000000000000000000000003" +
                    path[0][2:].zfill(64) +
                    path[1][2:].zfill(64) +
                    path[2][2:].zfill(64))

            result = ctx.rpc.eth_call(router_addr, data)
            raw = result[2:]
            sell_amount = int(raw[256:320], 16) if len(raw) >= 320 else 0

            if sell_amount > 0:
                return VerificationResult(
                    finding=finding,
                    confirmed=False,
                    confidence=0.85,
                    evidence=f"Buy+sell cycle returned {sell_amount} wei on {ctx.token.chain.name} — not a honeypot",
                )
            else:
                return VerificationResult(
                    finding=finding,
                    confirmed=True,
                    confidence=0.9,
                    evidence=f"Sell returned 0 on {ctx.token.chain.name} — cannot sell tokens",
                )
        except Exception as exc:
            return VerificationResult(
                finding=finding,
                confirmed=True,
                confidence=0.8,
                evidence=f"Sell simulation reverted on {ctx.token.chain.name}: {exc}",
            )
