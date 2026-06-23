from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evm.disassembler import disassemble


class BytecodeSstoreCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "bytecode_sstore"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "SSTORE without access control detected"

    @property
    def recommendation(self) -> str:
        return "Add owner/caller check before storage writes"

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
            if inst.name != "SSTORE":
                continue
            if not _has_access_check(instructions, i):
                return Finding(
                    check_name=self.name,
                    severity=self.severity,
                    description=f"SSTORE at offset {inst.offset} without visible access control",
                    recommendation=self.recommendation,
                    details={"offset": inst.offset},
                )
        return None


def _has_access_check(instructions: list, sstore_idx: int) -> bool:
    lookback = 30
    start = max(0, sstore_idx - lookback)
    for inst in instructions[start:sstore_idx]:
        if inst.name == "CALLER":
            return True
        if inst.name == "ORIGIN":
            return True
    return False
