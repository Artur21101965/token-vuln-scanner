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
        return "Manual verification required — simulate a full buy+sell cycle"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        return Finding(
            check_name=self.name,
            severity=self.severity,
            description="Honeypot detection requires swap simulation — flagged for manual review",
            recommendation=self.recommendation,
        )
