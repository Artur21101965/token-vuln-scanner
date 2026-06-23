from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evmole_utils import find_dangerous_functions, get_functions


class EvmoleFunctionDiscoveryCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "evmole_function_discovery"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "EVMole bytecode analysis found suspicious functions"

    @property
    def recommendation(self) -> str:
        return "Review flagged functions for access control vulnerabilities"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or code == "0x":
            return None

        dangerous = find_dangerous_functions(code)
        if not dangerous:
            return None

        known = [d for d in dangerous if not d.get("suspicious")]
        unknown = [d for d in dangerous if d.get("suspicious")]

        details = {"known_dangerous": known, "suspicious": unknown}

        if any(d.get("state_mutability") == "nonpayable" for d in dangerous):
            functions = get_functions(code)
            details["total_functions"] = len(functions)
            details["all_selectors"] = [fn.selector for fn in functions]

        return Finding(
            check_name=self.name,
            severity=self.severity if unknown else Severity.LOW,
            description=self._describe(known, unknown),
            recommendation=self.recommendation,
            details=details,
        )

    def _describe(self, known: list[dict], unknown: list[dict]) -> str:
        parts = []
        if known:
            sigs = [d["signature"] for d in known[:5]]
            parts.append(f"Known dangerous functions: {', '.join(sigs)}")
        if unknown:
            parts.append(f"Suspicious unknown functions: {len(unknown)}")
        return "; ".join(parts)
