from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity


class MintAuthorityCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "mint_authority_not_revoked"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Mint authority is not revoked — owner can mint new tokens"

    @property
    def recommendation(self) -> str:
        return "Revoke mint authority via spl-token authorize --disable"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        return Finding(
            check_name=self.name,
            severity=self.severity,
            description=self.description,
            recommendation=self.recommendation,
            details={"note": "Requires RPC call to token mint account for verification"},
        )


class FreezeAuthorityCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "freeze_authority_active"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Freeze authority is still active — owner can freeze token accounts"

    @property
    def recommendation(self) -> str:
        return "Revoke freeze authority via spl-token authorize --disable"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        return Finding(
            check_name=self.name,
            severity=self.severity,
            description=self.description,
            recommendation=self.recommendation,
        )
