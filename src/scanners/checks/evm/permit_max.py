"""Check: permit with type(uint256).max — anyone can get unlimited allowance."""
from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evmole_utils import get_selectors

PERMIT_SELECTORS = {"d505accf", "0d505acc", "f3995224", "8fcbaf0c",
                     "d505accf", "b7ab0db5", "26121ff0"}


class PermitMaxAllowanceCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "permit_max_allowance"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "permit signature — может разрешить неограниченный аппрув любому"

    @property
    def recommendation(self) -> str:
        return "Проверить валидацию подписи и nonce. Убедиться что permit не даёт type(uint256).max"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) <= 4:
            return None

        found_selectors = get_selectors(code)
        permitted = [s for s in PERMIT_SELECTORS if s in found_selectors]
        if not permitted:
            return None

        # Try calling permit with max allowance to our signer
        rpc = ctx.rpc
        for sel in permitted:
            # permit(owner, spender, value=MAX, deadline, v, r, s)
            try:
                # We can't sign a valid permit, but we can check if the function
                # lacks access control by calling with random signature
                gas = rpc.eth_call(ctx.token.address, "0x" + sel,
                    from_address="0x0000000000000000000000000000000000000001")
                if gas and gas != "0x":
                    return Finding(
                        check_name=self.name,
                        severity=self.severity,
                        description=f"permit селектор {sel} callable без подписи",
                        recommendation=self.recommendation,
                        details={"selector": sel},
                        confidence=0.6,
                    )
            except Exception:
                pass

        return None
