"""Check: unprotected skim/sync on AMM pairs — drain reserves."""
from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evmole_utils import get_selectors

SKIM_SYNC_SELECTORS = {"c95c03fb", "b1976bd9", "fff6cae9", "1cff79cd"}


class AmmSkimSyncCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "amm_skim_sync"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "AMM skim/sync без защиты — можно вывести резервы пары"

    @property
    def recommendation(self) -> str:
        return "Добавить onlyPool или onlyFactory модификатор на skim/sync"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) <= 4:
            return None

        found_selectors = get_selectors(code)

        for sel in SKIM_SYNC_SELECTORS:
            if sel in found_selectors:
                try:
                    gas = ctx.rpc.eth_call(
                        ctx.token.address, "0x" + sel,
                        from_address="0x0000000000000000000000000000000000000001"
                    )
                    if gas and gas != "0x":
                        return Finding(
                            check_name=self.name,
                            severity=self.severity,
                            description=f"skim/sync селектор {sel} callable",
                            recommendation=self.recommendation,
                            details={"selector": sel},
                            confidence=0.8,
                        )
                except Exception:
                    pass

        return None
