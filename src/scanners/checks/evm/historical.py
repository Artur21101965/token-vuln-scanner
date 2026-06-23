from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
OWNERSHIP_TOPIC = "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0"
UPGRADE_TOPIC = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"


class HistoricalAnalysisCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "historical_analysis"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Historical events analysis found suspicious patterns"

    @property
    def recommendation(self) -> str:
        return "Review token's event history for unusual mint/ownership/upgrade activity"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        issues: list[str] = []

        transfer_events = self._fetch_events(ctx, TRANSFER_TOPIC)
        if transfer_events is not None:
            mint_count = sum(1 for e in transfer_events
                             if e.get("topics", [""])[1] == "0x0000000000000000000000000000000000000000000000000000000000000000")
            if mint_count > 10:
                issues.append(f"{mint_count} mint events found (unusually high)")

            total_transfers = len(transfer_events)
            if total_transfers < 5 and total_transfers > 0:
                issues.append(f"Only {total_transfers} transfers in recent history (low activity)")

        owner_events = self._fetch_events(ctx, OWNERSHIP_TOPIC)
        if owner_events is not None and len(owner_events) > 3:
            issues.append(f"Ownership changed {len(owner_events)} times (unusually frequent)")

        upgrade_events = self._fetch_events(ctx, UPGRADE_TOPIC)
        if upgrade_events is not None and len(upgrade_events) > 0:
            issues.append(f"Implementation upgraded {len(upgrade_events)} times")

        if not issues:
            return None

        return Finding(
            check_name=self.name,
            severity=Severity.MEDIUM if len(issues) <= 1 else Severity.HIGH,
            description="; ".join(issues),
            recommendation=self.recommendation,
            details={"issues": issues},
        )

    def _fetch_events(self, ctx: CheckContext, topic: str, max_blocks: int = 50000) -> Optional[list[dict]]:
        try:
            latest = ctx.rpc.call("eth_blockNumber", [])
            if not latest or latest == "0x0":
                return None
            to_block = hex(int(latest, 16))
            from_block = hex(max(0, int(latest, 16) - max_blocks))
            logs = ctx.rpc.call("eth_getLogs", [{
                "address": ctx.token.address,
                "fromBlock": from_block,
                "toBlock": to_block,
                "topics": [topic],
            }])
            return logs if isinstance(logs, list) else None
        except Exception:
            return None
