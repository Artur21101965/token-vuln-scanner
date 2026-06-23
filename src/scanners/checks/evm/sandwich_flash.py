from typing import Optional
import httpx
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

DEXSCREENER_TOKEN_API = "https://api.dexscreener.com/latest/dex/tokens/{address}"
SWAP_TOPIC = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"

FLASH_LOAN_PROVIDERS = {
    "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9": "Aave V2",
    "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2": "Aave V3",
    "0x1E0447b19BB6EcFdAe1e4AE1694b0C3659614e4e": "dYdX",
    "0xBA12222222228d8Ba445958a75a0704d566BF2C8": "Balancer Vault",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    "0xE592427A0AEce92De3Edee1F18E0157C05861564": "Uniswap V3 Router",
    "0xDef1C0ded9bec7F1a1670819833240f027b25EfF": "0x Proxy",
}

RECENT_BLOCKS = 20000


class SandwichFlashCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "sandwich_flash_loan"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Suspected sandwich attack or flash loan activity detected"

    @property
    def recommendation(self) -> str:
        return "Monitor pool for MEV activity — sandwich attacks indicate high slippage risk"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        issues: list[str] = []

        sandwich = self._detect_sandwich(ctx)
        if sandwich:
            issues.append(sandwich)

        flash = self._detect_flash_loan(ctx)
        if flash:
            issues.append(flash)

        if not issues:
            return None

        return Finding(
            check_name=self.name,
            severity=self.severity,
            description="; ".join(issues),
            recommendation=self.recommendation,
            details={"sandwich": sandwich, "flash_loan": flash},
        )

    def _detect_sandwich(self, ctx: CheckContext) -> Optional[str]:
        pools = self._fetch_pools(ctx.token.address)
        if not pools:
            return None

        pool = pools[0]
        pair_addr = pool.get("pairAddress", "")
        if not pair_addr:
            return None

        swap_events = self._fetch_swap_events(ctx, pair_addr)
        if not swap_events:
            return None

        blocks_to_swaps: dict[str, list[str]] = {}
        for event in swap_events:
            block = event.get("blockNumber", "")
            if not block:
                continue
            sender = event.get("topics", ["", ""])[1][-40:].lower() if len(event.get("topics", [])) > 1 else ""
            if sender not in blocks_to_swaps.setdefault(block, []):
                blocks_to_swaps[block].append(sender)

        suspicious_blocks = [b for b, senders in blocks_to_swaps.items() if len(senders) >= 2]
        if suspicious_blocks:
            count = len(suspicious_blocks)
            return f"{count} block(s) with multiple swappers in pool {pair_addr[:10]} — possible sandwich"

        return None

    def _detect_flash_loan(self, ctx: CheckContext) -> Optional[str]:
        latest_block = self._get_latest_block(ctx)
        if latest_block is None:
            return None
        from_block = hex(max(0, latest_block - RECENT_BLOCKS))

        involved_providers: list[str] = []
        for provider_addr, label in FLASH_LOAN_PROVIDERS.items():
            try:
                logs = ctx.rpc.call("eth_getLogs", [{
                    "address": ctx.token.address,
                    "fromBlock": from_block,
                    "toBlock": "latest",
                    "topics": [None, None, "0x" + provider_addr[2:].zfill(64)],
                }])
                if isinstance(logs, list) and len(logs) > 0:
                    involved_providers.append(f"{label} ({logs[0].get('transactionHash', '')[:10]}...)")
            except Exception:
                continue

        if involved_providers:
            return f"Flash loan provider(s) involved: {', '.join(involved_providers)}"
        return None

    def _fetch_pools(self, token_address: str) -> list[dict]:
        try:
            resp = httpx.get(DEXSCREENER_TOKEN_API.format(address=token_address), timeout=10)
            resp.raise_for_status()
            data = resp.json()
            return data.get("pairs", [])
        except Exception:
            return []

    def _fetch_swap_events(self, ctx: CheckContext, pool_addr: str) -> Optional[list[dict]]:
        try:
            latest = ctx.rpc.call("eth_blockNumber", [])
            if not latest:
                return None
            to_block = hex(int(latest, 16))
            from_block = hex(max(0, int(latest, 16) - RECENT_BLOCKS))
            return ctx.rpc.call("eth_getLogs", [{
                "address": pool_addr,
                "fromBlock": from_block,
                "toBlock": to_block,
                "topics": [SWAP_TOPIC],
            }])
        except Exception:
            return None

    def _get_latest_block(self, ctx: CheckContext) -> Optional[int]:
        try:
            hex_val = ctx.rpc.call("eth_blockNumber", [])
            return int(hex_val, 16) if hex_val else None
        except Exception:
            return None
