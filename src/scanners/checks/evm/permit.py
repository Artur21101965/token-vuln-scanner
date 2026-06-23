from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

PERMIT_SELECTOR = "d505accf"


class PermitCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "permit_detected"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Contract supports EIP-2612 permit — signature phishing risk"

    @property
    def recommendation(self) -> str:
        return "Users should never sign permit messages from untrusted dApps; consider revoking permits via revoke.cash"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        abi_raw = ctx.data_collector.get_abi(ctx.token.address, ctx.token.chain)
        if abi_raw:
            try:
                import json
                for item in json.loads(abi_raw):
                    if not isinstance(item, dict):
                        continue
                    name = (item.get("name") or "").lower()
                    if name == "permit":
                        finding = Finding(
                            check_name=self.name,
                            severity=self.severity,
                            description=f"Permit function found in ABI — supports gasless approvals",
                            recommendation=self.recommendation,
                        )
                        finding._selector_based = True
                        return finding
            except json.JSONDecodeError:
                pass

        code = ctx.data_collector.get_code(ctx.token.address)
        if code and len(code) > 4:
            code_hex = code.lower().removeprefix("0x")
            if PERMIT_SELECTOR in code_hex:
                finding = Finding(
                    check_name=self.name,
                    severity=self.severity,
                    description="Permit selector d505accf found in bytecode — EIP-2612 approvals possible",
                    recommendation=self.recommendation,
                )
                finding._selector_based = True
                return finding

        return None
