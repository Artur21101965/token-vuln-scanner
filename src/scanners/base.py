from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from typing import Optional
from src.types import TokenInfo, PoolInfo, Finding, Severity, ScanReport
from src.data import DataCollector
from src.rpc import RpcClient
from src.db.deployer_store import DeployerStore


@dataclass
class CheckContext:
    token: TokenInfo
    pool: PoolInfo
    data_collector: DataCollector
    rpc: RpcClient
    deployer_store: Optional[DeployerStore] = None
    dispatch_selectors: set[str] = field(default_factory=set)
    has_fallback: bool = False


class BaseCheck(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    @abstractmethod
    def severity(self) -> Severity:
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        ...

    @property
    @abstractmethod
    def recommendation(self) -> str:
        ...

    @abstractmethod
    def run(self, ctx: CheckContext) -> Optional[Finding]:
        ...


class BaseScanner(ABC):
    def __init__(self, data_collector: DataCollector, rpc: RpcClient, deployer_store: Optional[DeployerStore] = None):
        self._data = data_collector
        self._rpc = rpc
        self._deployer_store = deployer_store

    @property
    @abstractmethod
    def checks(self) -> list[BaseCheck]:
        ...

    def scan(self, token: TokenInfo, pool: PoolInfo) -> ScanReport:
        ctx = CheckContext(
            token=token,
            pool=pool,
            data_collector=self._data,
            rpc=self._rpc,
            deployer_store=self._deployer_store,
        )
        bytecode = self._data.get_code(token.address) or ""
        if bytecode:
            from src.evm.dispatch_table import parse_dispatch_table
            selectors, _ = parse_dispatch_table(bytecode)
            ctx.dispatch_selectors = set(selectors.keys())
            ctx.has_fallback = self._data.fallback_detected(token.address)
        findings: list[Finding] = []
        for check in self.checks:
            try:
                result = check.run(ctx)
                if result is not None:
                    findings.append(result)
            except Exception as exc:
                findings.append(Finding(
                    check_name=check.name,
                    severity=Severity.MEDIUM,
                    description=f"Check failed with error: {exc}",
                    recommendation="Manual review recommended",
                ))
        return ScanReport(token=token, pool=pool, findings=findings)
