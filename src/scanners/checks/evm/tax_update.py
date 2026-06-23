from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

TAX_FUNC_NAMES = {"settax", "updatefee", "setbuyfee", "setsellfee", "updatetax", "setfeebps"}


class TaxUpdateCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "public_tax_update"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Tax/fee update function found — anyone could set 99% tax and trap holders"

    @property
    def recommendation(self) -> str:
        return "Ensure fee update functions are behind onlyOwner and ownership is renounced"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        abi_raw = ctx.data_collector.get_abi(ctx.token.address, ctx.token.chain)
        if abi_raw:
            try:
                import json
                for item in json.loads(abi_raw):
                    if not isinstance(item, dict):
                        continue
                    name = (item.get("name") or "").lower()
                    if name in TAX_FUNC_NAMES:
                        finding = Finding(
                            check_name=self.name,
                            severity=self.severity,
                            description=f"Tax/fee update function '{item.get('name')}' found in ABI",
                            recommendation=self.recommendation,
                        )
                        finding._selector_based = True
                        return finding
            except json.JSONDecodeError:
                pass
        return None
