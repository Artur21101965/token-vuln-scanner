from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evmole_utils import find_dangerous_functions

SWEEP_SELECTORS = {
    "00f714ce", "d0679d34", "b69ef8a8", "21df0da7",
    "b36a7c65", "811c39ab", "278d88cf",
    "693d09d3", "7c71ef48",
    "6198e339",
}


class UnprotectedSweepCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "unprotected_sweep"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Sweep/drain function found — can transfer ETH or tokens to any address"

    @property
    def recommendation(self) -> str:
        return "Remove sweep function or add owner-only access control"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or code == "0x":
            return None

        dangerous = find_dangerous_functions(code)
        sweep_funcs = []
        for fn in dangerous:
            sel_hex = fn.get("selector", "")
            if sel_hex in SWEEP_SELECTORS:
                sweep_funcs.append(fn)

        if not sweep_funcs:
            return None

        return Finding(
            check_name=self.name,
            severity=self.severity,
            description=f"Sweep/drain function(s) found: {len(sweep_funcs)}",
            recommendation=self.recommendation,
            details={"sweep_functions": [f.get("selector") for f in sweep_funcs]},
        )
