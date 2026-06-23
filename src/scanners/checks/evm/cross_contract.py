from typing import Optional
import httpx
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity
from src.evm.disassembler import disassemble

DEXSCREENER_TOKEN_API = "https://api.dexscreener.com/latest/dex/tokens/{address}"

SWEEP_SELECTORS = {
    "f2fde38b": "transferOwnership",
    "f4c5c2de": "sweep",
    "2e1a7d4d": "withdraw",
    "4094572c": "sweepETH",  # common sweep function hash
    "695b2a7e": "emergencyWithdraw",
    "61b1c7d4": "skim",  # Uniswap pair skim
    "ffb2c479": "sync",  # Uniswap pair sync
    "2a795b47": "donate",
    "cdca1753": "changeFee",
    "9ba2c8d0": "setSwapFee",
    "920f2302": "migrate",
    "a9059cbb": "transfer",
    "23b872dd": "transferFrom",
}

ROUTER_DRAIN_SELECTORS = {
    "f2fde38b": "transferOwnership",
    "40c10f19": "mint",
    "3659cfe6": "upgradeTo",
    "2e1a7d4d": "withdraw",
    "8129fc1c": "initialize",
}


class CrossContractCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "cross_contract"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Cross-contract analysis found suspicious pool/router functions"

    @property
    def recommendation(self) -> str:
        return "Review pool and router contracts for sweep/drain capabilities"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        pools = self._fetch_pools(ctx.token.address)
        if not pools:
            return None

        pool_findings: list[str] = []
        router_findings: list[str] = []

        for pool in pools[:5]:
            pair_addr = pool.get("pairAddress", "")
            if not pair_addr:
                continue
            dex = pool.get("dexId", "")
            issues = self._check_contract(pair_addr, ctx, SWEEP_SELECTORS)
            if issues:
                pool_findings.append(f"{dex}/{pair_addr[:10]}: {', '.join(issues)}")

            router_addr = self._guess_router(dex)
            if router_addr:
                router_issues = self._check_contract(router_addr, ctx, ROUTER_DRAIN_SELECTORS)
                if router_issues:
                    router_findings.append(f"{dex} router ({router_addr[:10]}): {', '.join(router_issues)}")

        if pool_findings or router_findings:
            desc_parts = []
            if pool_findings:
                desc_parts.append("Pool issues: " + " | ".join(pool_findings))
            if router_findings:
                desc_parts.append("Router issues: " + " | ".join(router_findings))
            return Finding(
                check_name=self.name,
                severity=self.severity,
                description="; ".join(desc_parts),
                recommendation=self.recommendation,
                details={"pools_checked": len(pools), "pool_findings": pool_findings, "router_findings": router_findings},
            )
        return None

    def _fetch_pools(self, token_address: str) -> list[dict]:
        try:
            resp = httpx.get(DEXSCREENER_TOKEN_API.format(address=token_address), timeout=10)
            resp.raise_for_status()
            data = resp.json()
            return data.get("pairs", [])
        except Exception:
            return []

    def _check_contract(self, address: str, ctx: CheckContext, selectors: dict) -> list[str]:
        try:
            code = ctx.data_collector.get_code(address, "latest")
        except Exception:
            return []
        if not code or code in ("0x", "0x0"):
            return []
        try:
            instructions = disassemble(code)
        except Exception:
            return []

        found: list[str] = []
        for inst in instructions:
            push_hex = inst.push_data.hex()
            if push_hex in selectors:
                found.append(selectors[push_hex])
        return found

    def _guess_router(self, dex: str) -> Optional[str]:
        routers = {
            "uniswap": "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
            "pancakeswap": "0x10ed43c718714eb63d5aa57b78b54704e256024e",
            "aerodrome": "0xcF77a3Ba9A5CA399B7c97c74d54e5b1beb874e43",
            "quickswap": "0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff",
            "camelot": "0xc873fEcbd354f5A56E00E710B90EF4201db2448d",
            "traderjoe": "0x60aE616a2155Ee3d9A68541Ba4544862310933d4",
            "sushiswap": "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F",
        }
        dex_lower = dex.lower()
        for key, addr in routers.items():
            if key in dex_lower:
                return addr
        return None
