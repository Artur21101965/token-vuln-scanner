import json
from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

MINT_SELECTORS = {
    "1249c58b",
    "a0712d68",
    "40c10f19",
    "3a4b66f1",
}


class MintCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "mint_function_unprotected"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Mint function exists and may not be properly restricted"

    @property
    def recommendation(self) -> str:
        return "Ensure mint is behind onlyOwner/onlyRole and renounce ownership"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        abi_raw = ctx.data_collector.get_abi(ctx.token.address, ctx.token.chain)
        if abi_raw:
            try:
                abi = json.loads(abi_raw)
                for item in abi:
                    if not isinstance(item, dict):
                        continue
                    name = item.get("name", "").lower()
                    if "mint" in name:
                        return Finding(
                            check_name=self.name,
                            severity=self.severity,
                            description=f"Mint function '{item.get('name')}' found in ABI",
                            recommendation=self.recommendation,
                        )
            except json.JSONDecodeError:
                pass

        code = ctx.data_collector.get_code(ctx.token.address)
        if code and len(code) > 4:
            code_hex = code.lower().removeprefix("0x")
            for sel in MINT_SELECTORS:
                if sel in code_hex:
                    return Finding(
                        check_name=self.name,
                        severity=self.severity,
                        description=f"Mint selector {sel} found in bytecode",
                        recommendation=self.recommendation,
                    )

        return None
