from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity


class CrossChainDeployerCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "high_risk_deployer"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Deployer has created tokens with critical findings across chains"

    @property
    def recommendation(self) -> str:
        return "Avoid tokens from multi-chain scam deployers — high probability of rug or honeypot"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        store = ctx.deployer_store
        if store is None:
            return None

        dc = ctx.data_collector
        creator = dc.get_creator_address(ctx.token.address, ctx.token.chain)
        if creator is None:
            return None

        stats = store.get_stats(creator)
        if stats["token_count"] < 3:
            return None

        critical_pct = stats["critical_count"] / stats["token_count"] if stats["token_count"] > 0 else 0

        if critical_pct < 0.5:
            return None

        return Finding(
            check_name=self.name,
            severity=Severity.CRITICAL,
            description=(
                f"Deployer {creator[:10]}... created {stats['token_count']} tokens across chains, "
                f"{stats['critical_count']} ({critical_pct:.0%}) with critical findings"
            ),
            recommendation=self.recommendation,
            details={
                "deployer": creator,
                "token_count": stats["token_count"],
                "critical_count": stats["critical_count"],
            },
        )
