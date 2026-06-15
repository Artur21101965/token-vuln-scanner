import json
from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity


class BlacklistCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "blacklist_function"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Contract has blacklist/whitelist functions — owner can block addresses"

    @property
    def recommendation(self) -> str:
        return "Renounce ownership or remove blacklist functions"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        abi = ctx.data_collector.get_abi(ctx.token.address, ctx.token.chain)
        if abi:
            try:
                for item in json.loads(abi):
                    if not isinstance(item, dict):
                        continue
                    name = (item.get("name") or "").lower()
                    if any(x in name for x in ("blacklist", "whitelist")):
                        return Finding(
                            check_name=self.name,
                            severity=self.severity,
                            description=f"Blacklist/whitelist function: {item.get('name')}",
                            recommendation=self.recommendation,
                        )
            except json.JSONDecodeError:
                pass
        return None
