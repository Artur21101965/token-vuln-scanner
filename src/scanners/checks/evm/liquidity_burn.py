from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

BURN_ADDRESSES = (
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
)

LP_BURN_THRESHOLD = 0.99


class LiquidityBurnedCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "liquidity_not_burned"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Liquidity pool tokens are not burned — creator can remove liquidity"

    @property
    def recommendation(self) -> str:
        return "Only invest if LP tokens are burned or sent to a dead address (locked liquidity)"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        pair = ctx.pool.address
        if not pair:
            return None

        data = ctx.data_collector
        total_lp = data.get_total_supply(pair)
        if total_lp == 0:
            return None

        burned = 0
        for addr in BURN_ADDRESSES:
            burned += data.get_balance_of(pair, addr)

        burned_pct = burned / total_lp
        if burned_pct >= LP_BURN_THRESHOLD:
            return None

        creator = data.get_creator_address(ctx.token.address, ctx.token.chain)
        creator_lp = data.get_balance_of(pair, creator) if creator else 0

        if creator_lp > 0:
            desc = f"Creator holds {creator_lp / 10**18:.2f} LP tokens ({creator_lp / total_lp:.1%} of pool)"
            sev = Severity.CRITICAL if (creator_lp / total_lp) > 0.10 else Severity.HIGH
        else:
            desc = f"Only {burned_pct:.1%} of LP tokens burned — {1 - burned_pct:.1%} remains"
            sev = Severity.MEDIUM

        return Finding(
            check_name=self.name,
            severity=sev,
            description=desc,
            recommendation=self.recommendation,
            details={"total_lp": str(total_lp), "burned_pct": str(burned_pct)},
        )
