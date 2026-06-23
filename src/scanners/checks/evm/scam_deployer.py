from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity


class ScamDeployerCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "known_scammer_deployer"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Token deployed by known scammer address"

    @property
    def recommendation(self) -> str:
        return "Avoid any token from this deployer — they have deployed multiple scam tokens"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        store = ctx.deployer_store
        if store is None:
            return None

        dc = ctx.data_collector
        creator = dc.get_creator_address(ctx.token.address, ctx.token.chain)
        if creator is None:
            return None

        if not store.is_known_scammer(creator):
            return None

        stats = store.get_stats(creator)
        return Finding(
            check_name=self.name,
            severity=self.severity,
            description=(
                f"Known scammer deployer {creator[:12]}... has deployed {stats['token_count']} tokens "
                f"({stats['critical_count']} with critical findings)"
            ),
            recommendation=self.recommendation,
        )
