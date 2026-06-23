"""Check: delegatecall to user-controlled address — full contract takeover."""
from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evmole_utils import get_selectors

DC_SELECTORS = {"b61d27f6", "61461954", "1cff79cd", "5cffe9de",
                 "619a309f", "09c5eabe", "522f6815"}


class DelegatecallInjectionCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "delegatecall_injection"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "delegatecall с пользовательским адресом — полный контроль"

    @property
    def recommendation(self) -> str:
        return "Ограничить адреса для delegatecall белым списком или толькоOwner"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) <= 4:
            return None

        found_selectors = get_selectors(code)
        code_hex = code.lower().replace("0x", "")

        dc_hits = [s for s in DC_SELECTORS if s in code_hex]
        if not dc_hits:
            return None

        # Check if DELEGATECALL opcode exists in bytecode
        if "f4" not in code_hex:
            return None

        # Try calling execute/delegatecall-like functions
        for sel in dc_hits[:3]:
            try:
                gas = ctx.rpc.eth_call(
                    ctx.token.address, "0x" + sel,
                    from_address="0x0000000000000000000000000000000000000001"
                )
                if gas and gas != "0x":
                    return Finding(
                        check_name=self.name,
                        severity=self.severity,
                        description=f"delegatecall-функция {sel} callable",
                        recommendation=self.recommendation,
                        details={"selector": sel},
                        confidence=0.85,
                    )
            except Exception:
                pass

        return None
