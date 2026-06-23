from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

IMPLEMENTATION_SLOTS = [
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
    "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7",
]

UPGRADE_SELECTORS = {"3659cfe6", "4f1ef286", "a3b2b1fe"}


class UninitializedProxyCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "uninitialized_proxy"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Proxy implementation slot is zero — anyone can set implementation"

    @property
    def recommendation(self) -> str:
        return "Deploy and set implementation address, disable upgradeTo"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or "delegatecall" not in code.lower():
            return None

        impl_found = False
        dc = ctx.data_collector
        for slot in IMPLEMENTATION_SLOTS:
            try:
                raw = dc.get_storage_at(ctx.token.address, int(slot, 16))
                addr = "0x" + raw[26:] if len(raw) >= 66 else raw
                if addr and int(addr, 16) != 0:
                    impl_found = True
                    break
            except Exception:
                continue

        if impl_found:
            return None

        has_upgrade_selector = False
        from src.evmole_utils import get_selectors
        try:
            found = get_selectors(code)
            has_upgrade_selector = bool(found & UPGRADE_SELECTORS)
        except Exception:
            code_hex = code.lower().removeprefix("0x")
            has_upgrade_selector = any(sel in code_hex for sel in UPGRADE_SELECTORS)

        if not has_upgrade_selector:
            return None

        return Finding(
            check_name=self.name,
            severity=self.severity,
            description="Proxy has no implementation set but has upgradeTo selector",
            recommendation=self.recommendation,
            details={"status": "uninitialized", "has_upgrade_selector": True},
        )
