from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

BURN_ADDRESSES = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
    "0x000000000000000000000000000000000000dEaD",
}

OWNER_SELECTOR = "0x8da5cb5b"


class OwnerNotRenouncedCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "owner_not_renounced"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Owner address is not renounced (not address(0) or burn address)"

    @property
    def recommendation(self) -> str:
        return "Renounce ownership or transfer to a timelock contract"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        try:
            result = ctx.rpc.eth_call(ctx.token.address, OWNER_SELECTOR)
            owner = "0x" + result[-40:].lower()
            if owner in BURN_ADDRESSES:
                return None
            return Finding(
                check_name=self.name,
                severity=self.severity,
                description=f"Owner {owner} is not renounced",
                recommendation=self.recommendation,
            )
        except Exception:
            return None
