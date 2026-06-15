from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

PAUSE_SELECTORS = {"8456cb59", "3f4ba83a", "5c975abb"}


class PausableCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "pausable_token"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Token can be paused — owner can halt trading"

    @property
    def recommendation(self) -> str:
        return "Renounce ownership or remove pause functions"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if code:
            for sel in PAUSE_SELECTORS:
                if sel in code.lower():
                    return Finding(
                        check_name=self.name,
                        severity=self.severity,
                        description=self.description,
                        recommendation=self.recommendation,
                    )
        return None
