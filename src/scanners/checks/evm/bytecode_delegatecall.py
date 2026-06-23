from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evm.disassembler import disassemble


class BytecodeDelegatecallCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "bytecode_delegatecall"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "DELEGATECALL to dynamic address (possible proxy abuse)"

    @property
    def recommendation(self) -> str:
        return "Use hardcoded contract address for DELEGATECALL or add owner-only guard"

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
            if inst.name != "DELEGATECALL":
                continue
            if _is_dynamic_target(instructions, i):
                return Finding(
                    check_name=self.name,
                    severity=self.severity,
                    description=f"DELEGATECALL at offset {inst.offset} uses dynamic address (not hardcoded)",
                    recommendation=self.recommendation,
                    details={"offset": inst.offset},
                )
        return None


def _is_dynamic_target(instructions: list, delegatecall_idx: int) -> bool:
    lookback = 50
    start = max(0, delegatecall_idx - lookback)
    for inst in reversed(instructions[start:delegatecall_idx]):
        if inst.name == "CALLDATALOAD":
            return True
        if inst.name == "SLOAD":
            return True
        if inst.name in ("CALLER", "ADDRESS", "ORIGIN"):
            return True
    return False
