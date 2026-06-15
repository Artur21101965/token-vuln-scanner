from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity


class ReentrancyCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "potential_reentrancy"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Contract uses .call() — potential reentrancy risk"

    @property
    def recommendation(self) -> str:
        return "Ensure CEI pattern or reentrancy guard is used"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if code and ".call(" in code.lower():
            return Finding(
                check_name=self.name,
                severity=self.severity,
                description=self.description,
                recommendation=self.recommendation,
            )
        return None
