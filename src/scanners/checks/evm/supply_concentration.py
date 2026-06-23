from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

BURN_ADDRESSES = (
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
)

SUPPLY_THRESHOLD = 0.50
HONEYPOT_THRESHOLD = 0.99


class SupplyConcentrationCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "supply_concentration"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Token supply is highly concentrated in one wallet"

    @property
    def recommendation(self) -> str:
        return "High concentration means price can be easily manipulated or dumped by the holder"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        data = ctx.data_collector
        token = ctx.token.address

        total = data.get_total_supply(token)
        if total == 0:
            return None

        creator = data.get_creator_address(token, ctx.token.chain)
        targets = [
            ("creator", creator),
        ]
        if ctx.pool.address:
            targets.append(("pair", ctx.pool.address))

        for label, address in targets:
            if not address or address.lower() in BURN_ADDRESSES:
                continue
            balance = data.get_balance_of(token, address)
            if balance == 0:
                continue
            pct = balance / total
            if pct >= SUPPLY_THRESHOLD:
                sev = Severity.CRITICAL if pct >= HONEYPOT_THRESHOLD else Severity.HIGH
                return Finding(
                    check_name=self.name,
                    severity=sev,
                    description=f"{label.title()} holds {pct:.1%} of total supply ({balance / 10**18:.2f} tokens)",
                    recommendation=self.recommendation,
                    details={"holder": address, "balance": str(balance), "total_supply": str(total)},
                )

        return None
