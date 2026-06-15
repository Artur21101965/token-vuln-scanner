from src.scanners.base import BaseScanner, BaseCheck
from src.scanners.checks.solana import ALL_SOLANA_CHECKS


class SolanaScanner(BaseScanner):
    @property
    def checks(self) -> list[BaseCheck]:
        return [cls() for cls in ALL_SOLANA_CHECKS]
