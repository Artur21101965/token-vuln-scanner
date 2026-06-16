from typing import Optional
from src.verifiers.base import Verifier, VerificationResult
from src.types import Finding, Severity
from src.scanners.base import CheckContext

UNISWAP_V2_ROUTER = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
WETH_ADDRESS = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
GET_AMOUNTS_OUT_SIG = "0xd06ca61f"  # getAmountsOut(uint256,address[])


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
                confirmed=True,
                confidence=0.7,
                evidence="No pair address — cannot simulate swap, keeping flag",
            )

        try:
            path = [
                WETH_ADDRESS,
                ctx.token.address,
                WETH_ADDRESS,
            ]
            amount = 10 ** 18  # 1 ETH worth
            data = GET_AMOUNTS_OUT_SIG + hex(amount)[2:].zfill(64) + "0000000000000000000000000000000000000000000000000000000000000060" + \
                   "0000000000000000000000000000000000000000000000000000000000000003" + \
                   path[0][2:].zfill(64) + path[1][2:].zfill(64) + path[2][2:].zfill(64)

            result = ctx.rpc.eth_call(UNISWAP_V2_ROUTER, data)
            raw = result[2:]  # strip 0x
            # ABI: offset(32) + length(32) + amounts[0](32) + amounts[1](32) + amounts[2](32)
            # amounts[2] = final WETH amount after token→WETH swap
            sell_amount = int(raw[256:320], 16) if len(raw) >= 320 else 0

            if sell_amount > 0:
                return VerificationResult(
                    finding=finding,
                    confirmed=False,
                    confidence=0.85,
                    evidence=f"Swap simulation succeeded: buy+sell cycle returned {sell_amount} wei",
                )
            else:
                return VerificationResult(
                    finding=finding,
                    confirmed=True,
                    confidence=0.9,
                    evidence="Swap simulation returned 0 on sell — cannot sell tokens",
                )

        except Exception as exc:
            return VerificationResult(
                finding=finding,
                confirmed=True,
                confidence=0.8,
                evidence=f"Sell simulation reverted: {exc}",
            )
