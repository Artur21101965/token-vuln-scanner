from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

# EIP-1967 proxy storage slots
IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

# Common token storage slots
TOTAL_SUPPLY_SLOT = "0x0000000000000000000000000000000000000000000000000000000000000002"
OWNER_SLOT_OPENZEPPELIN = "0x0000000000000000000000000000000000000000000000000000000000000000"

# EIP-1967 UUPS / transparent proxy
ERC1967_IMPLEMENTATION_SLOT = IMPLEMENTATION_SLOT

# keccak256("owner") / keccak256("_owner") — computed literals
OWNER_SLOT_KECCAK = "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0"
OWNER_SLOT_UNDERSCORE = "0x4e70b9e5e7fb8f82ed2f63081e2d8220ec0e54b18b0b4ee7056a8999b5f3b8d"

# Standard ERC20 slot for name/owner in some implementations
SLOT_NAMES = {
    TOTAL_SUPPLY_SLOT: "totalSupply (slot 2)",
    OWNER_SLOT_OPENZEPPELIN: "_owner (slot 0, OpenZeppelin style)",
    IMPLEMENTATION_SLOT: "EIP-1967 implementation",
    ADMIN_SLOT: "EIP-1967 admin",
    BEACON_SLOT: "EIP-1967 beacon",
    OWNER_SLOT_KECCAK: "owner() (keccak256)",
    OWNER_SLOT_UNDERSCORE: "_owner (keccak256)",
}

ZERO_ADDR = "0x0000000000000000000000000000000000000000"

CRITICAL_SLOTS = [
    IMPLEMENTATION_SLOT,
    ADMIN_SLOT,
    BEACON_SLOT,
    OWNER_SLOT_OPENZEPPELIN,
    OWNER_SLOT_KECCAK,
    OWNER_SLOT_UNDERSCORE,
    TOTAL_SUPPLY_SLOT,
]


class StorageLayoutCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "storage_layout_audit"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Storage layout audit found anomalous contract state"

    @property
    def recommendation(self) -> str:
        return "Investigate anomalous storage slot values — they may indicate proxy misconfiguration or malicious contract"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        issues: list[str] = []

        for slot in CRITICAL_SLOTS:
            value = self._read_slot(ctx, slot)
            if value is None:
                continue
            label = SLOT_NAMES.get(slot, slot)
            clean_value = value if value.startswith("0x") else "0x" + value
            clean_value = "0x" + clean_value[2:].zfill(64)
            if slot in (IMPLEMENTATION_SLOT, ADMIN_SLOT, BEACON_SLOT):
                addr = "0x" + clean_value[-40:]
                if addr == ZERO_ADDR:
                    issues.append(f"{label} is zero address (proxy misconfigured)")
                else:
                    code_size = self._get_code_size(ctx, addr)
                    if code_size == 0:
                        issues.append(f"{label} ({addr}) has no code — may be selfdestructed")
            elif slot in (OWNER_SLOT_OPENZEPPELIN, OWNER_SLOT_KECCAK, OWNER_SLOT_UNDERSCORE):
                addr = "0x" + clean_value[-40:] if len(clean_value) >= 42 else ZERO_ADDR
                if addr == ZERO_ADDR:
                    issues.append("Owner is zero address (contract renounced)")
            elif slot == TOTAL_SUPPLY_SLOT:
                val_int = int(clean_value, 16)
                if val_int == 0:
                    issues.append("totalSupply slot reads 0 — may be malicious or dead")

        if not issues:
            return None

        return Finding(
            check_name=self.name,
            severity=Severity.MEDIUM,
            description="; ".join(issues),
            recommendation=self.recommendation,
            details={"issues": issues},
        )

    def _read_slot(self, ctx: CheckContext, slot: str) -> Optional[str]:
        try:
            return ctx.rpc.call("eth_getStorageAt", [ctx.token.address, slot, "latest"])
        except Exception:
            return None

    def _get_code_size(self, ctx: CheckContext, addr: str) -> int:
        try:
            code = ctx.data_collector.get_code(addr)
            if code and code != "0x":
                return (len(code) - 2) // 2
            return 0
        except Exception:
            return 0
