from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity


class TokenExtensionsCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "token_2022_extensions"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Token uses Token-2022 extensions — may have hidden features"

    @property
    def recommendation(self) -> str:
        return "Review token extension configuration"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        return Finding(
            check_name=self.name,
            severity=self.severity,
            description=self.description,
            recommendation=self.recommendation,
        )
