from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.scanners.checks.solana.util import get_mint_account, hex_to_base58
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
        parsed = get_mint_account(ctx)
        if not parsed:
            return None

        mint_auth = parsed.get("mint_authority", "")

        if mint_auth and int(mint_auth, 16) != 0:
            b58 = hex_to_base58(mint_auth)
            return Finding(
                check_name=self.name,
                severity=self.severity,
                description=self.description,
                recommendation=self.recommendation,
                details={
                    "mint_authority": mint_auth,
                    "mint_authority_base58": b58,
                    "authority_address": b58,
                    "supply": str(parsed.get("supply", 0)),
                },
            )
        return None


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
        parsed = get_mint_account(ctx)
        if not parsed:
            return None

        freeze_auth = parsed.get("freeze_authority", "")

        if freeze_auth and int(freeze_auth, 16) != 0:
            b58 = hex_to_base58(freeze_auth)
            return Finding(
                check_name=self.name,
                severity=self.severity,
                description=self.description,
                recommendation=self.recommendation,
                details={
                    "freeze_authority": freeze_auth,
                    "freeze_authority_base58": b58,
                    "authority_address": b58,
                },
            )
        return None
