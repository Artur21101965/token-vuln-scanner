import json
from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evmole_utils import get_selectors, analyze_bytecode

UPGRADE_FUNC_NAMES = {"upgradeto", "upgradetoandcall", "setimplementation"}
UPGRADE_SELECTORS = {"3659cfe6", "4f1ef286", "a3b2b1fe"}


class UpgradeCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "unprotected_upgrade"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Upgrade function found — anyone could upgrade the contract to a malicious implementation"

    @property
    def recommendation(self) -> str:
        return "Ensure upgrade functions are behind onlyOwner and that owner is renounced or timelocked"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        abi_raw = ctx.data_collector.get_abi(ctx.token.address, ctx.token.chain)
        if abi_raw:
            try:
                for item in json.loads(abi_raw):
                    if not isinstance(item, dict):
                        continue
                    name = (item.get("name") or "").lower()
                    if name in UPGRADE_FUNC_NAMES:
                        finding = Finding(
                            check_name=self.name,
                            severity=self.severity,
                            description=f"Upgrade function '{item.get('name')}' found in ABI",
                            recommendation=self.recommendation,
                        )
                        finding._selector_based = True
                        return finding
            except json.JSONDecodeError:
                pass

        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) <= 4:
            return None

        found_selectors = get_selectors(code)
        for sel in UPGRADE_SELECTORS:
            if sel in found_selectors:
                return self._make_finding(sel, confirmed=True)

        info = analyze_bytecode(code)
        has_dispatch = info is not None and len(info.functions) > 0
        if has_dispatch:
            return None

        code_hex = code.lower().removeprefix("0x")
        for sel in UPGRADE_SELECTORS:
            if sel in code_hex:
                return self._make_finding(sel, confirmed=False)

        return None

    def _make_finding(self, selector: str, confirmed: bool) -> Finding:
        desc = f"Upgrade selector {selector} found in bytecode dispatch table"
        if not confirmed:
            desc += " (unconfirmed dispatch match)"
        finding = Finding(
            check_name=self.name,
            severity=self.severity,
            description=desc,
            recommendation=self.recommendation,
            details={"selector": selector, "confirmed": confirmed},
        )
        finding._selector_based = True
        return finding
