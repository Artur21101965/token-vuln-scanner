from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity


class HoneypotCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "potential_honeypot"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Token may be a honeypot (cannot sell after buying)"

    @property
    def recommendation(self) -> str:
        return "Run a buy+sell swap simulation to confirm"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        if not ctx.pool.address:
            return None
        return Finding(
            check_name=self.name,
            severity=self.severity,
            description="Honeypot detection requires swap simulation — flagged for verification",
            recommendation=self.recommendation,
        )
