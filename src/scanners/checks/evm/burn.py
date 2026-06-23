from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

BURN_SELECTORS = {
    "42966c68",
    "79cc6790",
}

BURN_FUNCTION_NAMES = {"burn", "burnfrom"}


class PublicBurnCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "public_burn"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Public burn function found — anyone can burn tokens"

    @property
    def recommendation(self) -> str:
        return "Ensure burn functions are behind onlyOwner or a separate allowance mechanism"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        abi_raw = ctx.data_collector.get_abi(ctx.token.address, ctx.token.chain)
        if abi_raw:
            try:
                import json
                for item in json.loads(abi_raw):
                    if not isinstance(item, dict):
                        continue
                    name = (item.get("name") or "").lower()
                    if name in BURN_FUNCTION_NAMES:
                        finding = Finding(
                            check_name=self.name,
                            severity=self.severity,
                            description=f"Public burn function '{item.get('name')}' found in ABI",
                            recommendation=self.recommendation,
                        )
                        finding._selector_based = True
                        return finding
            except json.JSONDecodeError:
                pass

        code = ctx.data_collector.get_code(ctx.token.address)
        if code and len(code) > 4:
            code_hex = code.lower().removeprefix("0x")
            for sel in BURN_SELECTORS:
                if sel in code_hex:
                    finding = Finding(
                        check_name=self.name,
                        severity=self.severity,
                        description=f"Burn selector {sel} found in bytecode",
                        recommendation=self.recommendation,
                    )
                    finding._selector_based = True
                    return finding

        return None
