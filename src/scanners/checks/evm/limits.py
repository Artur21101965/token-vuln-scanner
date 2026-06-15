import json
from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity


class MaxTxLimitCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "max_transaction_limit"

    @property
    def severity(self) -> Severity:
        return Severity.LOW

    @property
    def description(self) -> str:
        return "Token has max transaction amount"

    @property
    def recommendation(self) -> str:
        return "Review limit — may be used to block large sells"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        abi = ctx.data_collector.get_abi(ctx.token.address, ctx.token.chain)
        if abi:
            try:
                for item in json.loads(abi):
                    name = (item.get("name") or "").lower()
                    if any(x in name for x in ("maxtx", "max_tx", "_maxtx")):
                        return Finding(check_name=self.name, severity=self.severity, description=self.description, recommendation=self.recommendation)
            except json.JSONDecodeError:
                pass
        return None


class MaxWalletLimitCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "max_wallet_limit"

    @property
    def severity(self) -> Severity:
        return Severity.LOW

    @property
    def description(self) -> str:
        return "Token has max wallet amount"

    @property
    def recommendation(self) -> str:
        return "Review limit — may prevent large holders"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        abi = ctx.data_collector.get_abi(ctx.token.address, ctx.token.chain)
        if abi:
            try:
                for item in json.loads(abi):
                    name = (item.get("name") or "").lower()
                    if any(x in name for x in ("maxwallet", "max_wallet", "_maxwallet")):
                        return Finding(check_name=self.name, severity=self.severity, description=self.description, recommendation=self.recommendation)
            except json.JSONDecodeError:
                pass
        return None
