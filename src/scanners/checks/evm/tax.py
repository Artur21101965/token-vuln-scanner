import json
from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity


class HighTaxCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "high_transaction_tax"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Token may have high buy/sell tax (>10%)"

    @property
    def recommendation(self) -> str:
        return "Review tax functions in contract. High tax may indicate rug risk."

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        abi = ctx.data_collector.get_abi(ctx.token.address, ctx.token.chain)
        if abi:
            try:
                for item in json.loads(abi):
                    if not isinstance(item, dict):
                        continue
                    name = (item.get("name") or "").lower()
                    if "tax" in name or "fee" in name:
                        return Finding(
                            check_name=self.name,
                            severity=self.severity,
                            description=f"Tax/fee function found: {item.get('name')}",
                            recommendation=self.recommendation,
                        )
            except json.JSONDecodeError:
                pass
        return None
