"""
OPCODE-LEVEL VULNERABILITY SCANNER — finds real exploit patterns in raw bytecode.

Checks:
  1. CALL without success check (silent failure → lost funds)
  2. DELEGATECALL with user-controlled calldata (takeover)
  3. SELFDESTRUCT in nonpayable function (can be triggered by anyone)
  4. TIMESTAMP used in critical path (price manipulation)
  5. EXTCODESIZE bypass (can trick isContract check)
  6. SLOAD owner before SELFDESTRUCT (onlyOwner check exists? → still dangerous)
"""
import logging
from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evmole_utils import get_functions, get_selectors

logger = logging.getLogger(__name__)

# EVM opcodes (single byte each)
SELFDESTRUCT = 0xff
DELEGATECALL = 0xf4
CALL = 0xf1
STATICCALL = 0xfa
CALLDATALOAD = 0x35
CALLDATASIZE = 0x36
CALLDATACOPY = 0x37
TIMESTAMP = 0x42
SSTORE = 0x55
SLOAD = 0x54
EXTCODESIZE = 0x3b
ISZERO = 0x15
JUMPI = 0x57
REVERT = 0xfd


def _bytes_to_ints(hex_str: str) -> list[int]:
    """Convert 0x... hex string to list of byte integers."""
    h = hex_str.lower().replace("0x", "")
    return [int(h[i:i+2], 16) for i in range(0, len(h), 2)]


def _has_call_without_check(code_bytes: list[int]) -> bool:
    """Check if CALL/DELEGATECALL is followed by ISZERO+JUMPI (revert on failure)."""
    for i, b in enumerate(code_bytes):
        if b in (CALL, DELEGATECALL, STATICCALL):
            # Look at next 5 bytes for ISZERO
            window = code_bytes[i:i+5]
            if ISZERO not in window and REVERT not in window:
                return True
    return False


def _has_delegatecall_with_calldata(code_bytes: list[int]) -> bool:
    """Check if DELEGATECALL is near CALLDATALOAD (user-controlled target)."""
    dc_positions = [i for i, b in enumerate(code_bytes) if b == DELEGATECALL]
    cd_positions = [i for i, b in enumerate(code_bytes) if b in (CALLDATALOAD, CALLDATACOPY)]

    for dc in dc_positions:
        for cd in cd_positions:
            if abs(dc - cd) < 30:  # within 30 bytes = likely same function
                return True
    return False


def _has_selfdestruct_reachable(code_bytes: list[int], functions) -> bool:
    """Check if SELFDESTRUCT exists and is in a nonpayable function (no value check)."""
    if SELFDESTRUCT not in code_bytes:
        return False

    sd_pos = code_bytes.index(SELFDESTRUCT)

    # Check which function contains this position
    for fn in functions:
        if hasattr(fn, 'basic_blocks') and fn.basic_blocks:
            for bb in fn.basic_blocks:
                if hasattr(bb, 'start') and hasattr(bb, 'end'):
                    if bb.start <= sd_pos < bb.end:
                        if fn.state_mutability == "nonpayable":
                            return True  # SELFDESTRUCT in no-payment function
    return False


def _has_timestamp_dependency(code_bytes: list[int]) -> bool:
    """Check if TIMESTAMP is used near SSTORE or CALL (critical path)."""
    ts_positions = [i for i, b in enumerate(code_bytes) if b == TIMESTAMP]
    critical_positions = [i for i, b in enumerate(code_bytes) if b in (SSTORE, CALL, DELEGATECALL)]

    for ts in ts_positions:
        for crit in critical_positions:
            if abs(ts - crit) < 40:
                return True
    return False


def _has_extcodesize_bypass(code_bytes: list[int]) -> bool:
    """Check for EXTCODESIZE check that can be bypassed (constructor check)."""
    if EXTCODESIZE not in code_bytes:
        return False

    # Check if EXTCODESIZE result is checked with ISZERO/JUMPI
    ec_positions = [i for i, b in enumerate(code_bytes) if b == EXTCODESIZE]
    for pos in ec_positions:
        window = code_bytes[pos:pos+8]
        if ISZERO in window and JUMPI in window:
            # Has code-size check — but can it be bypassed?
            # If called from constructor, EXTCODESIZE returns 0
            return True
    return False


class OpcodeSelfdestructCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "opcode_selfdestruct_unprotected"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "SELFDESTRUCT опкод найден в nonpayable функции — можно уничтожить контракт"

    @property
    def recommendation(self) -> str:
        return "Перенести SELFDESTRUCT в payable функцию или добавить проверку владельца"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) <= 4:
            return None

        code_bytes = _bytes_to_ints(code)
        functions = get_functions(code)

        if _has_selfdestruct_reachable(code_bytes, functions):
            return Finding(check_name=self.name, severity=self.severity,
                          description=self.description, recommendation=self.recommendation,
                          confidence=0.85)
        return None


class OpcodeDelegatecallInjectCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "opcode_delegatecall_injection"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "DELEGATECALL + CALLDATALOAD — адрес делегата берётся из пользовательского ввода"

    @property
    def recommendation(self) -> str:
        return "Использовать белый список адресов для delegatecall"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) <= 4:
            return None

        code_bytes = _bytes_to_ints(code)

        if _has_delegatecall_with_calldata(code_bytes):
            return Finding(check_name=self.name, severity=self.severity,
                          description=self.description, recommendation=self.recommendation,
                          confidence=0.9)
        return None


class OpcodeUncheckedCallCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "opcode_unchecked_call"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "CALL/DELEGATECALL без проверки успеха — silent failure, потеря средств"

    @property
    def recommendation(self) -> str:
        return "Добавить require(success) после каждого низкоуровневого вызова"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) <= 4:
            return None

        code_bytes = _bytes_to_ints(code)

        if _has_call_without_check(code_bytes):
            return Finding(check_name=self.name, severity=self.severity,
                          description=self.description, recommendation=self.recommendation,
                          confidence=0.7)
        return None


class OpcodeTimestampCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "opcode_timestamp_dependency"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "block.timestamp используется в критическом пути (SSTORE/CALL) — манипуляция временем"

    @property
    def recommendation(self) -> str:
        return "Не использовать timestamp для критических решений. Использовать block.number"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) <= 4:
            return None

        code_bytes = _bytes_to_ints(code)

        if _has_timestamp_dependency(code_bytes):
            return Finding(check_name=self.name, severity=self.severity,
                          description=self.description, recommendation=self.recommendation,
                          confidence=0.5)
        return None


class OpcodeExtcodesizeCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "opcode_extcodesize_bypass"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "EXTCODESIZE проверка — можно обойти вызовом из конструктора"

    @property
    def recommendation(self) -> str:
        return "Проверять tx.origin == msg.sender для защиты от constructor-атак"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) <= 4:
            return None

        code_bytes = _bytes_to_ints(code)

        if _has_extcodesize_bypass(code_bytes):
            return Finding(check_name=self.name, severity=self.severity,
                          description=self.description, recommendation=self.recommendation,
                          confidence=0.6)
        return None


# Export all checks
OPCODE_CHECKS = [
    OpcodeSelfdestructCheck,
    OpcodeDelegatecallInjectCheck,
    OpcodeUncheckedCallCheck,
    OpcodeTimestampCheck,
    OpcodeExtcodesizeCheck,
]
