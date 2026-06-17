from typing import TYPE_CHECKING, Optional
from src.scanners.base import BaseScanner, BaseCheck, CheckContext
from src.scanners.checks.evm import ALL_EVM_CHECKS
from src.verifiers.runner import VerifierRunner
from src.types import TokenInfo, PoolInfo, ScanReport, Severity
from src.db.deployer_store import DeployerStore
from src.known_contracts import is_known_contract

if TYPE_CHECKING:
    from src.exploit_executor import ExploitExecutor


class EvmScanner(BaseScanner):
    def __init__(self, data_collector, rpc, verifier_runner: Optional[VerifierRunner] = None,
                 deployer_store: Optional[DeployerStore] = None,
                 executor: Optional["ExploitExecutor"] = None):
        super().__init__(data_collector, rpc, deployer_store=deployer_store)
        self._verifier_runner = verifier_runner
        self._executor = executor

    @property
    def checks(self) -> list[BaseCheck]:
        return [cls() for cls in ALL_EVM_CHECKS]

    def scan(self, token: TokenInfo, pool: PoolInfo) -> ScanReport:
        report = super().scan(token, pool)
        ctx = CheckContext(
            token=token,
            pool=pool,
            data_collector=self._data,
            rpc=self._rpc,
            deployer_store=self._deployer_store,
        )
        if self._verifier_runner:
            report.findings = self._verifier_runner.verify_findings(ctx, report.findings)

        known = is_known_contract(token.address, token.chain.name.lower())
        if known:
            filtered = []
            skip = known.get("skip_checks", set())
            for f in report.findings:
                if f.check_name in skip:
                    f.severity = Severity.INFO
                    f.description += f" — known safe ({known['name']})"
                filtered.append(f)
            report.findings = filtered

        if self._executor:
            for f in report.findings:
                if self._executor.can_execute(f):
                    conf = f.details.get("verification_confidence", 0)
                    if conf >= 0.9:
                        logger = logging.getLogger(__name__)
                        logger.warning("Exploiting %s on %s (conf=%s)...",
                                       f.check_name, token.symbol, conf)
                        self._executor.execute(ctx, f)

        return report
