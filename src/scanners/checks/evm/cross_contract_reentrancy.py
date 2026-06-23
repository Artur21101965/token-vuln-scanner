from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evmole_utils import get_selectors

KNOWN_DEX_ROUTERS = {
    "10ed43c718714eb63d5aa57b78b54704e256024e": "PancakeSwap V2",
    "7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    "def1c0ded9bec7f1a1670819833240f499b25efd": "0x Proxy",
    "e592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
    "68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap V3 Router 2",
    "d9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router",
    "1b02da8cb0d097eb8d57a175b88c7d8b47997506": "SushiSwap Router (old)",
    "a5e0829caced8ffdd4de3c43696c57f7d7a678ff": "QuickSwap",
    "c873fecbd354f5a56e00e710b90ef4201db2448d": "Camelot",
    "60ae616a2155ee3d9a68541ba4544862310933d4": "Trader Joe",
    "cf77a3ba9a5ca399b7c97c74d54e5b1beb874e43": "Aerodrome",
    "ba12222222228d8ba445958a75a0704d566bf2c8": "Balancer V2 Vault",
    "1111111254eeb25477b68fb85ed929f73a960582": "1inch V5",
}

TRANSFER_SELECTORS = {"a9059cbb", "23b872dd"}


class CrossContractReentrancyCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "cross_contract_reentrancy"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Token transfer flow calls DEX router — potential double-processing exploit"

    @property
    def recommendation(self) -> str:
        return ("Audit _beforeTokenTransfer / _afterTokenTransfer hooks for external DEX calls. "
                "This pattern was used in the Buy the DIP exploit (111k USDC drained via double-processing).")

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or code == "0x" or len(code) < 42:
            return None

        code_hex = code.lower().removeprefix("0x")

        selectors = get_selectors(code)
        has_transfer_funcs = bool(TRANSFER_SELECTORS & selectors)

        found_routers = []
        for addr_hex, name in KNOWN_DEX_ROUTERS.items():
            idx = code_hex.find(addr_hex)
            if idx >= 0:
                found_routers.append({"router": name, "address": "0x" + addr_hex, "offset": idx})

        call_count = code_hex.count("f1")

        if has_transfer_funcs and found_routers and call_count > 0:
            routers_str = ", ".join(f"{r['router']} at offset {r['offset']}" for r in found_routers)
            return Finding(
                check_name=self.name,
                severity=Severity.CRITICAL,
                description=(
                    f"ERC20 with transfer/transferFrom makes DELEGATECALL to DEX router(s): {routers_str}. "
                    "Transfer hook likely interacts with DEX — potential double-processing exploit pattern."
                ),
                recommendation=self.recommendation,
                details={
                    "routers": found_routers,
                    "call_count": call_count,
                    "has_transfer_funcs": has_transfer_funcs,
                },
            )

        if found_routers and call_count > 0:
            routers_str = ", ".join(f"{r['router']}" for r in found_routers)
            return Finding(
                check_name=self.name,
                severity=Severity.HIGH,
                description=f"Contract references DEX router(s) {routers_str} and has CALL opcode",
                recommendation="Verify the purpose of DEX router interaction",
                details={"routers": found_routers, "call_count": call_count},
            )

        if has_transfer_funcs and call_count > 5:
            return Finding(
                check_name=self.name,
                severity=Severity.LOW,
                description=f"ERC20 with {call_count} CALL opcodes — may interact with external contracts during transfer",
                recommendation="Audit transfer hooks for external dependencies",
                details={"call_count": call_count},
            )

        return None
