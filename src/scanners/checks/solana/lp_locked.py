from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity


class LpLockedSolanaCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "lp_not_locked_solana"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "LP tokens may not be locked on Solana"

    @property
    def recommendation(self) -> str:
        return "Use Streamflow or similar locker on Solana"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        return Finding(
            check_name=self.name,
            severity=self.severity,
            description=self.description,
            recommendation=self.recommendation,
        )
