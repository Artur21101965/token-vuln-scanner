import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.scam_deployer import ScamDeployerCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.data import DataCollector
from src.rpc import RpcClient
from src.db.deployer_store import DeployerStore


def make_ctx(dc=None, rpc=None, store=None):
    return CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=1000),
        data_collector=dc or Mock(spec=DataCollector),
        rpc=rpc or Mock(spec=RpcClient),
        deployer_store=store,
    )


class TestScamDeployerCheck:
    check = ScamDeployerCheck()

    def test_name_and_severity(self):
        assert self.check.name == "known_scammer_deployer"
        assert self.check.severity == Severity.CRITICAL

    def test_returns_finding_when_deployer_is_scammer(self):
        dc = Mock(spec=DataCollector)
        dc.get_creator_address.return_value = "0xscammer"
        store = Mock(spec=DeployerStore)
        store.is_known_scammer.return_value = True
        store.get_stats.return_value = {"token_count": 5, "critical_count": 3}

        finding = self.check.run(make_ctx(dc=dc, store=store))
        assert finding is not None
        assert "known scammer" in finding.description.lower()

    def test_returns_none_when_deployer_not_scammer(self):
        dc = Mock(spec=DataCollector)
        dc.get_creator_address.return_value = "0xsafe"
        store = Mock(spec=DeployerStore)
        store.is_known_scammer.return_value = False

        finding = self.check.run(make_ctx(dc=dc, store=store))
        assert finding is None

    def test_returns_none_when_no_deployer_found(self):
        dc = Mock(spec=DataCollector)
        dc.get_creator_address.return_value = None

        finding = self.check.run(make_ctx(dc=dc, store=Mock(spec=DeployerStore)))
        assert finding is None

    def test_returns_none_when_no_store(self):
        finding = self.check.run(make_ctx())
        assert finding is None
