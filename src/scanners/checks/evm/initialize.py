import json
from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evmole_utils import get_selectors, analyze_bytecode

INIT_SELECTORS = {"8129fc1c", "1c5b8f7b", "6a98c6a3", "a627c6c6", "c4d66de8"}


class InitializeCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "unprotected_initialize"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Initialize function found — anyone might re-initialize the contract"

    @property
    def recommendation(self) -> str:
        return "Ensure initialize() is behind an initializer modifier and cannot be called again"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        abi_raw = ctx.data_collector.get_abi(ctx.token.address, ctx.token.chain)
        if abi_raw:
            try:
                for item in json.loads(abi_raw):
                    if not isinstance(item, dict):
                        continue
                    name = (item.get("name") or "").lower()
                    if name == "initialize" or name.startswith("initialize"):
                        finding = Finding(
                            check_name=self.name,
                            severity=self.severity,
                            description=f"Initialize function '{item.get('name')}' found in ABI",
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
        for sel in INIT_SELECTORS:
            if sel in found_selectors:
                return self._make_finding(sel, confirmed=True)

        info = analyze_bytecode(code)
        has_dispatch = info is not None and len(info.functions) > 0
        if has_dispatch:
            return None

        code_hex = code.lower().removeprefix("0x")
        for sel in INIT_SELECTORS:
            if sel in code_hex:
                return self._make_finding(sel, confirmed=False)

        return None

    def _make_finding(self, selector: str, confirmed: bool) -> Finding:
        desc = f"Initialize selector {selector} found in bytecode dispatch table"
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
