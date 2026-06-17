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
        return "Contract contains SELFDESTRUCT — can be destroyed"

    @property
    def recommendation(self) -> str:
        return "If SELFDESTRUCT is callable by anyone, the contract can be erased and funds lost"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) < 10:
            return None

        if "selfdestruct" in code.lower():
            return Finding(
                check_name=self.name,
                severity=Severity.CRITICAL,
                description="Source code mentions 'selfdestruct' — may be callable",
                recommendation=self.recommendation,
            )

        code_hex = code.lower().removeprefix("0x")
        if "ff" in code_hex:
            return None  # bytecode-only match is too unreliable — false positive on most contracts

        return None
