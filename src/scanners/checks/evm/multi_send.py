from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
MULTI_SEND_THRESHOLD = 50
SCAN_BLOCKS = 100


class MultiSendCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "multi_send_detected"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Token distributed to many wallets in a single transaction (possible pump distribution)"

    @property
    def recommendation(self) -> str:
        return "Check if holders are organic; multi-send to many wallets is common in pump-and-dump schemes"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        if ctx.token.chain.name.lower() == "solana":
            return None

        try:
            current = ctx.rpc.get_block_number()
        except Exception:
            return None

        from_block = max(0, current - SCAN_BLOCKS)
        try:
            logs = ctx.rpc.get_logs(
                from_block=hex(from_block),
                to_block=hex(current),
                address=ctx.token.address,
                topics=[TRANSFER_TOPIC],
            )
        except Exception:
            return None

        tx_recipients: dict[str, set[str]] = {}
        for log in logs:
            tx_hash = log.get("transactionHash", "")
            if not tx_hash:
                continue
            topics = log.get("topics", [])
            if len(topics) < 3:
                continue
            to_addr = topics[2]
            if tx_hash not in tx_recipients:
                tx_recipients[tx_hash] = set()
            tx_recipients[tx_hash].add(to_addr)

        max_recipients = max((len(addrs) for addrs in tx_recipients.values()), default=0)
        if max_recipients < MULTI_SEND_THRESHOLD:
            return None

        return Finding(
            check_name=self.name,
            severity=self.severity,
            description=f"Single tx distributed tokens to {max_recipients} unique addresses in last {SCAN_BLOCKS} blocks",
            recommendation=self.recommendation,
        )
