from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

DANGEROUS_APPROVE_NAMES = {"approveeveryone", "approveall", "setallowanceforall"}
DANGEROUS_APPROVE_SELECTOR = "da682aeb"


class ApproveAllCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "unprotected_approve_all"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Anyone-allowing approve function found — attacker can steal all tokens"

    @property
    def recommendation(self) -> str:
        return "Ensure approve functions only allow caller to approve their own allowance"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        abi_raw = ctx.data_collector.get_abi(ctx.token.address, ctx.token.chain)
        if abi_raw:
            try:
                import json
                for item in json.loads(abi_raw):
                    if not isinstance(item, dict):
                        continue
                    name = (item.get("name") or "").lower()
                    if name in DANGEROUS_APPROVE_NAMES:
                        finding = Finding(
                            check_name=self.name,
                            severity=self.severity,
                            description=f"Dangerous approve function '{item.get('name')}' found in ABI",
                            recommendation=self.recommendation,
                        )
                        finding._selector_based = True
                        return finding
            except json.JSONDecodeError:
                pass

        code = ctx.data_collector.get_code(ctx.token.address)
        if code and len(code) > 4:
            code_hex = code.lower().removeprefix("0x")
            if DANGEROUS_APPROVE_SELECTOR in code_hex:
                finding = Finding(
                    check_name=self.name,
                    severity=self.severity,
                    description=f"Non-standard approve selector {DANGEROUS_APPROVE_SELECTOR} found in bytecode — possible approve-all attack",
                    recommendation=self.recommendation,
                )
                finding._selector_based = True
                return finding

        return None
