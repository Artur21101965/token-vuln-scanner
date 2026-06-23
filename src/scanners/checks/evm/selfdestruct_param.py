from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evm.disassembler import disassemble
from src.evmole_utils import get_functions


class SelfdestructWithParamCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "exposed_selfdestruct_with_param"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "SELFDESTRUCT with address parameter — can redirect contract balance to any address"

    @property
    def recommendation(self) -> str:
        return "Remove SELFDESTRUCT or add owner-only guard"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        try:
            code = ctx.data_collector.get_code(ctx.token.address, "latest")
        except Exception:
            return None
        if not code or code in ("0x", "0x0"):
            return None
        try:
            instructions = disassemble(code)
        except Exception:
            return None
        try:
            functions = get_functions(code)
        except Exception:
            functions = []

        has_address_funcs = [fn for fn in functions if "address" in (fn.arguments or "").lower()]

        for i, inst in enumerate(instructions):
            if inst.name != "SELFDESTRUCT":
                continue
            if _has_guard(instructions, i):
                continue
            selector = _find_matching_selector(instructions, i, has_address_funcs)
            if selector:
                return Finding(
                    check_name=self.name,
                    severity=self.severity,
                    description=f"SELFDESTRUCT with address parameter at offset {inst.offset}",
                    recommendation=self.recommendation,
                    details={"selector": selector, "offset": inst.offset, "arg_functions": [fn.selector for fn in has_address_funcs]},
                )

        return None


def _has_guard(instructions: list, sd_idx: int) -> bool:
    lookback = 30
    start = max(0, sd_idx - lookback)
    has_caller = False
    has_eq = False
    for inst in instructions[start:sd_idx]:
        if inst.name == "CALLER":
            has_caller = True
        elif inst.name == "EQ" and has_caller:
            has_eq = True
        elif inst.name == "JUMPI" and has_eq:
            return True
    return False


def _find_matching_selector(instructions: list, sd_idx: int, address_funcs: list) -> Optional[str]:
    lookback = 20
    start = max(0, sd_idx - lookback)
    has_calldataload = False
    for inst in instructions[start:sd_idx]:
        if inst.name == "CALLDATALOAD":
            has_calldataload = True
            break
        if inst.name == "CALLDATASIZE":
            has_calldataload = True
            break
    if not has_calldataload:
        return None
    if address_funcs:
        return address_funcs[0].selector
    return None
