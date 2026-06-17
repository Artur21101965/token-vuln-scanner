from typing import Optional
from src.scanners.base import BaseScanner, BaseCheck, CheckContext
from src.scanners.checks.solana import ALL_SOLANA_CHECKS
from src.verifiers.runner import VerifierRunner
from src.types import TokenInfo, PoolInfo, ScanReport


class SolanaScanner(BaseScanner):
    def __init__(self, data_collector, rpc,
                 verifier_runner: Optional[VerifierRunner] = None):
        super().__init__(data_collector, rpc)
        self._verifier_runner = verifier_runner

    @property
    def checks(self) -> list[BaseCheck]:
        return [cls() for cls in ALL_SOLANA_CHECKS]

    def scan(self, token: TokenInfo, pool: PoolInfo) -> ScanReport:
        report = super().scan(token, pool)
        ctx = CheckContext(
            token=token,
            pool=pool,
            data_collector=self._data,
            rpc=self._rpc,
        )
        if self._verifier_runner:
            report.findings = self._verifier_runner.verify_findings(ctx, report.findings)
        return report
