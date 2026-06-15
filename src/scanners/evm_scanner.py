from src.scanners.base import BaseScanner, BaseCheck
from src.scanners.checks.evm import ALL_EVM_CHECKS


class EvmScanner(BaseScanner):
    @property
    def checks(self) -> list[BaseCheck]:
        return [cls() for cls in ALL_EVM_CHECKS]
