from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

MINT_SELECTORS = {"40c10f19", "2b6b4408", "4f2be91f", "a0712d68", "731133e9", "6a627842", "70288125", "9b51f390"}


class SupplyChangeCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "unprotected_mint"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Mint function detected in bytecode — supply may increase arbitrarily"

    @property
    def recommendation(self) -> str:
        return "Ensure mint functions are behind access control and have supply caps"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) < 10:
            return None

        code_hex = code.lower().removeprefix("0x")
        found = [s for s in MINT_SELECTORS if s in code_hex]
        if not found:
            return None

        return Finding(
            check_name=self.name,
            severity=self.severity,
            description=f"Mint selector(s) found: {', '.join('0x'+s for s in found)}",
            recommendation=self.recommendation,
            details={"selectors": found},
        )
