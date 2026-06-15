from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity


class PoolOwnershipCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "pool_ownership_not_renounced"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Raydium pool owner can remove liquidity without notice"

    @property
    def recommendation(self) -> str:
        return "Verify pool owner key is burned or timelocked"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        return Finding(
            check_name=self.name,
            severity=self.severity,
            description=self.description,
            recommendation=self.recommendation,
        )
