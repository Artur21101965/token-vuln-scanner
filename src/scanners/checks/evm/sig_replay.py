"""Check: signature without nonce/deadline — replay attack possible."""
from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evmole_utils import get_functions, analyze_bytecode


class SignatureReplayCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "signature_replay"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Подпись без nonce/deadline — возможна replay-атака"

    @property
    def recommendation(self) -> str:
        return "Добавить nonce и deadline в хеш подписи"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) <= 4:
            return None

        info = analyze_bytecode(code)
        if not info or not info.functions:
            return None

        code_hex = code.lower().replace("0x", "")

        # Check for EIP-712 DOMAIN_SEPARATOR or ecrecover usage
        has_ecrecover = "00" in code_hex  # ecrecover precompile address
        has_signature = any(
            "sign" in fn.selector or "permit" in fn.selector or "verify" in fn.selector
            for fn in info.functions
        )

        if not (has_ecrecover and has_signature):
            return None

        # Check if nonce/deadline pattern exists in bytecode
        has_nonce = "6e6f6e6365" in code_hex or "6e6f6e636500" in code_hex  # "nonce" in hex
        has_deadline = "646561646c696e65" in code_hex  # "deadline" in hex

        if not has_nonce and not has_deadline:
            return Finding(
                check_name=self.name,
                severity=self.severity,
                description="Контракт использует ecrecover/verify без nonce/deadline в байткоде",
                recommendation=self.recommendation,
                confidence=0.4,
            )

        return None
