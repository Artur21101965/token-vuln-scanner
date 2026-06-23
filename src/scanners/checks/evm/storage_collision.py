"""Storage collision + Unchecked ERC20 return checks."""
from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evmole_utils import get_functions, get_selectors

# Known proxy storage slots (EIP-1967, OpenZeppelin)
PROXY_SLOTS = {
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc": "implementation (EIP-1967)",
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103": "admin (EIP-1967)",
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50": "beacon (EIP-1967)",
    "0x9a7d42a7b43b150b69b52db4faaa09b1b0f8f61b6606e06e878be47085aef632": "OpenZeppelin v5 proxy owner",
    "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7": "UUPS proxiable UUID",
}


class ProxyStorageCollisionCheck(BaseCheck):
    """Check if a proxy's storage slots overlap with implementation storage."""

    @property
    def name(self) -> str:
        return "proxy_storage_collision"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Слоты прокси конфликтуют с хранилищем реализации — можно перезаписать implementation"

    @property
    def recommendation(self) -> str:
        return "Использовать EIP-1967 слоты в реализации или наследовать StorageCollisionProtection"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) <= 4:
            return None

        # Check if this is a proxy (has DELEGATECALL)
        code_hex = code.lower().replace("0x", "")
        if "f4" not in code_hex:  # DELEGATECALL opcode
            return None

        rpc = ctx.rpc
        addr = ctx.token.address

        # Read implementation slot (EIP-1967)
        impl_slot = int("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)

        try:
            impl_raw = rpc.get_storage_at(addr, impl_slot)
            impl_addr = "0x" + impl_raw[-40:] if impl_raw and impl_raw != "0x" else ""
            if not impl_addr or int(impl_addr, 16) == 0:
                return None
        except Exception:
            return None

        # Get implementation bytecode
        try:
            impl_code = rpc.eth_get_code(impl_addr)
            if not impl_code or len(impl_code) <= 4:
                return Finding(
                    check_name=self.name,
                    severity=self.severity,
                    description="Implementation контракт пуст — можно задеплоить свой код",
                    recommendation=self.recommendation,
                    confidence=0.95,
                    details={"impl_addr": impl_addr, "impl_code_empty": True},
                )
        except Exception:
            pass

        # Check if implementation uses any proxy slots
        from src.evmole_utils import analyze_bytecode
        info = analyze_bytecode(impl_code)
        if not info or not info.storage:
            return None

        collisions = []
        for slot_name, slot_hex in PROXY_SLOTS.items():
            slot_int = int(slot_hex, 16)
            # Check if this proxy slot is used by the implementation
            try:
                val = rpc.get_storage_at(impl_addr, slot_int)
                if val and val != "0x" + "0" * 64:
                    collisions.append(f"{slot_name} = занят в implementation")
            except Exception:
                continue

        if collisions:
            return Finding(
                check_name=self.name,
                severity=self.severity,
                description=f"Найдено {len(collisions)} конфликтов слотов хранилища: {', '.join(collisions[:3])}",
                recommendation=self.recommendation,
                confidence=0.8 if len(collisions) >= 2 else 0.5,
                details={"collisions": collisions},
            )

        return None


class UncheckedERC20ReturnCheck(BaseCheck):
    """Check for contracts that use ERC20 transfer/transferFrom without checking return value."""

    @property
    def name(self) -> str:
        return "unchecked_erc20_return"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Не проверяется возврат transfer/transferFrom — USDT и другие токены не возвращают bool"

    @property
    def recommendation(self) -> str:
        return "Использовать SafeERC20.safeTransfer или проверять возвращаемое значение"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) <= 4:
            return None

        code_hex = code.lower().replace("0x", "")

        # Look for transfer/transferFrom selectors in bytecode
        transfer_sel = "a9059cbb"  # transfer(address,uint256)
        transferfrom_sel = "23b872dd"  # transferFrom(address,address,uint256)

        has_transfer = transfer_sel in code_hex
        has_transferfrom = transferfrom_sel in code_hex

        if not (has_transfer or has_transferfrom):
            return None

        # Check if SafeERC20 is used (has safeTransfer pattern)
        safe_transfer_sel = "423f6cef"  # Not exact, but SafeERC20 uses low-level call
        if safe_transfer_sel in code_hex:
            return None  # Might be using SafeERC20

        # The mere presence of transfer selectors without safeTransfer is suspicious
        # Most modern contracts use SafeERC20
        findings = get_functions(code)
        has_erc20_pattern = any(
            "transfer" in (fn.arguments or "").lower()
            for fn in (findings or [])
        )

        if has_transfer and has_transferfrom and not safe_transfer_sel in code_hex:
            return Finding(
                check_name=self.name,
                severity=self.severity,
                description="Контракт использует transfer/transferFrom без SafeERC20 — риск для токенов без bool return",
                recommendation=self.recommendation,
                confidence=0.4,  # Low confidence — many contracts handle this properly
            )

        return None
