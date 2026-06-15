from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

TOTAL_SUPPLY_SELECTOR = "0x18160ddd"
BALANCE_OF_SELECTOR = "0x70a08231"
BURN_ADDRESS = "0x000000000000000000000000000000000000dead"


class LpNotBurnedCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "lp_tokens_not_burned"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "LP tokens are not sent to a burn address"

    @property
    def recommendation(self) -> str:
        return "Send LP tokens to a burn address or lock them in a locker"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        try:
            total_supply_raw = ctx.rpc.eth_call(ctx.pool.address, TOTAL_SUPPLY_SELECTOR)
            total = int(total_supply_raw, 16)
            if total == 0:
                return None

            balance_data = BALANCE_OF_SELECTOR + BURN_ADDRESS[2:].zfill(64)
            balance_raw = ctx.rpc.eth_call(ctx.pool.address, balance_data)
            balance_burn = int(balance_raw, 16)

            if balance_burn >= total:
                return None

            pct_unburned = ((total - balance_burn) / total) * 100
            return Finding(
                check_name=self.name,
                severity=self.severity,
                description=f"{pct_unburned:.1f}% of LP tokens are not burned",
                recommendation=self.recommendation,
                details={
                    "total_supply": str(total),
                    "burned": str(balance_burn),
                    "pct_unburned": str(round(pct_unburned, 1)),
                },
            )
        except Exception:
            return None
