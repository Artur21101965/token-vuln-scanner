from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evm.disassembler import disassemble


class BytecodeSelfdestructCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "bytecode_selfdestruct"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "SELFDESTRUCT found without access control"

    @property
    def recommendation(self) -> str:
        return "Remove SELFDESTRUCT or add caller/owner guard"

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

        for i, inst in enumerate(instructions):
            if inst.name != "SELFDESTRUCT":
                continue
            if not _has_guard(instructions, i):
                return Finding(
                    check_name=self.name,
                    severity=self.severity,
                    description=f"SELFDESTRUCT at offset {inst.offset} without access control",
                    recommendation=self.recommendation,
                    details={"offset": inst.offset},
                )
        return None


def _has_guard(instructions: list, selfdestruct_idx: int) -> bool:
    lookback = 30
    start = max(0, selfdestruct_idx - lookback)
    has_caller = False
    has_eq = False
    for inst in instructions[start:selfdestruct_idx]:
        if inst.name == "CALLER":
            has_caller = True
        elif inst.name == "EQ" and has_caller:
            has_eq = True
        elif inst.name == "JUMPI" and has_eq:
            return True
    return False
