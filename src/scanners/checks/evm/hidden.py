from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity


class HiddenSelfdestructCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "selfdestruct_in_code"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Contract may contain SELFDESTRUCT opcode (0xFF)"

    @property
    def recommendation(self) -> str:
        return "Owner can destroy contract and drain funds"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if code and "selfdestruct" in code.lower():
            return Finding(
                check_name=self.name,
                severity=self.severity,
                description="Contract source mentions 'selfdestruct'",
                recommendation=self.recommendation,
            )
        return None
