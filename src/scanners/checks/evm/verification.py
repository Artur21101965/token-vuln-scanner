from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity


class UnverifiedContractCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "unverified_contract"

    @property
    def severity(self) -> Severity:
        return Severity.LOW

    @property
    def description(self) -> str:
        return "Contract source code is not verified on the explorer"

    @property
    def recommendation(self) -> str:
        return "Unverified code can hide malicious logic — prefer audited, verified contracts"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        if ctx.data_collector.is_verified(ctx.token.address, ctx.token.chain):
            return None
        return Finding(
            check_name=self.name,
            severity=self.severity,
            description="Contract source code not verified on block explorer",
            recommendation=self.recommendation,
        )
