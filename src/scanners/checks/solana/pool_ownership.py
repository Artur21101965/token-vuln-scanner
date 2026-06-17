from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.scanners.checks.solana.util import hex_to_base58
from src.types import Finding, Severity


class PoolOwnershipCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "pool_ownership_not_renounced"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Raydium pool owner can remove liquidity without notice"

    @property
    def recommendation(self) -> str:
        return "Verify pool owner key is burned or timelocked"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        if not ctx.pool.address:
            return None
        try:
            result = ctx.rpc.call("getAccountInfo", [
                ctx.pool.address,
                {"encoding": "base64"},
            ])
        except Exception:
            return None

        info = result.get("result") or result
        account = info.get("value") or info if isinstance(info, dict) else {}
        raw_data = ""
        if isinstance(account, dict):
            raw_data = (account.get("data") or [None, None])[0] or ""

        if not raw_data:
            return None

        import base64
        try:
            data = base64.b64decode(raw_data)
        except Exception:
            return None

        if len(data) < 248:
            return None

        owner_bytes = data[216:248]
        import binascii
        owner_hex = binascii.hexlify(owner_bytes).decode()

        if int(owner_hex, 16) != 0:
            b58 = hex_to_base58(owner_hex)
            return Finding(
                check_name=self.name,
                severity=self.severity,
                description=self.description,
                recommendation=self.recommendation,
                details={
                    "pool_owner": owner_hex,
                    "owner_address": owner_hex,
                    "owner_base58": b58,
                    "authority_address": b58,
                },
            )
        return None
