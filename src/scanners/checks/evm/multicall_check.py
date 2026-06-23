"""Check: multicall without msg.sender validation — arbitrary execution."""
from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evmole_utils import get_selectors

MULTICALL_SELECTORS = {"ac9650d8", "252dba42", "5ae401dc", "ca350aa6",
                        "a4f9edbf", "79820ceb", "38ed1739"}


class MulticallUncheckedCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "multicall_unchecked"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "multicall без проверки msg.sender — можно выполнить чужие вызовы"

    @property
    def recommendation(self) -> str:
        return "Добавить require(msg.sender == original) в multicall"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) <= 4:
            return None

        found_selectors = get_selectors(code)
        mc_hits = [s for s in MULTICALL_SELECTORS if s in found_selectors]
        if not mc_hits:
            return None

        # Try calling multicall with empty data — if it doesn't revert, might be vulnerable
        for sel in mc_hits[:3]:
            try:
                gas = ctx.rpc.eth_call(
                    ctx.token.address, "0x" + sel,
                    from_address="0x0000000000000000000000000000000000000001"
                )
                if gas and gas != "0x":
                    return Finding(
                        check_name=self.name,
                        severity=self.severity,
                        description=f"multicall селектор {sel} callable без ограничений",
                        recommendation=self.recommendation,
                        details={"selector": sel},
                        confidence=0.5,
                    )
            except Exception:
                pass

        return None
