import json
from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity


class AccessControlCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "access_control_active"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Contract uses AccessControl — roles may still be active"

    @property
    def recommendation(self) -> str:
        return "Verify all roles are renounced"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        abi = ctx.data_collector.get_abi(ctx.token.address, ctx.token.chain)
        if abi:
            try:
                for item in json.loads(abi):
                    name = (item.get("name") or "").lower()
                    if any(x in name for x in ("grantrole", "revokerole", "renouncerole", "default_admin_role")):
                        return Finding(
                            check_name=self.name,
                            severity=self.severity,
                            description=f"AccessControl function: {item.get('name')}",
                            recommendation=self.recommendation,
                        )
            except json.JSONDecodeError:
                pass
        return None
