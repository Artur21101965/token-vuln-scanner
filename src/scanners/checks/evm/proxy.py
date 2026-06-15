from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity


class ProxyCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "upgradeable_proxy"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Contract uses delegatecall — may be upgradeable proxy"

    @property
    def recommendation(self) -> str:
        return "Ensure proxy admin is renounced or timelocked"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if code and "delegatecall" in code.lower():
            return Finding(
                check_name=self.name,
                severity=self.severity,
                description=self.description,
                recommendation=self.recommendation,
            )
        return None
