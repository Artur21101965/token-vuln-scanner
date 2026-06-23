import json
import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.initialize import InitializeCheck
from src.scanners.checks.evm.upgrade import UpgradeCheck
from src.scanners.base import CheckContext
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.data import DataCollector
from src.rpc import RpcClient


def make_ctx(code: str = "", abi: str = ""):
    dc = Mock(spec=DataCollector)
    dc.get_code.return_value = code
    dc.get_abi.return_value = abi
    return CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=1000),
        data_collector=dc,
        rpc=Mock(spec=RpcClient),
    )


class TestInitializeCheck:
    check = InitializeCheck()

    def test_name_and_severity(self):
        assert self.check.name == "unprotected_initialize"
        assert self.check.severity == Severity.CRITICAL

    def test_detects_initialize_in_abi(self):
        abi = json.dumps([
            {"type": "function", "name": "initialize", "inputs": []},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None
        assert "initialize" in finding.description.lower()

    def test_detects_initialize_with_params_in_abi(self):
        abi = json.dumps([
            {"type": "function", "name": "initialize", "inputs": [{"type": "address"}, {"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_detects_initialize_selector_in_bytecode(self):
        code = "0x6080" + "8129fc1c" + "6040"
        finding = self.check.run(make_ctx(code=code))
        assert finding is not None
        assert "selector 8129fc1c" in finding.description

    def test_returns_none_for_clean_contract(self):
        code = "0x6080604052604052"
        finding = self.check.run(make_ctx(code=code, abi="[]"))
        assert finding is None

    def test_returns_none_when_no_data(self):
        finding = self.check.run(make_ctx(code="0x", abi="[]"))
        assert finding is None

    def test_does_not_flag_transfer(self):
        abi = json.dumps([
            {"type": "function", "name": "transfer", "inputs": [{"type": "address"}, {"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is None


class TestUpgradeCheck:
    check = UpgradeCheck()

    def test_name_and_severity(self):
        assert self.check.name == "unprotected_upgrade"
        assert self.check.severity == Severity.CRITICAL

    def test_detects_upgrade_to_in_abi(self):
        abi = json.dumps([
            {"type": "function", "name": "upgradeTo", "inputs": [{"type": "address"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None
        assert "upgradeTo" in finding.description

    def test_detects_upgrade_to_and_call_in_abi(self):
        abi = json.dumps([
            {"type": "function", "name": "upgradeToAndCall", "inputs": [{"type": "address"}, {"type": "bytes"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_detects_set_implementation_in_abi(self):
        abi = json.dumps([
            {"type": "function", "name": "setImplementation", "inputs": [{"type": "address"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_detects_upgrade_selector_in_bytecode(self):
        code = "0x6080" + "3659cfe6" + "6040"
        finding = self.check.run(make_ctx(code=code))
        assert finding is not None
        assert "selector 3659cfe6" in finding.description

    def test_detects_upgrade_to_and_call_selector_in_bytecode(self):
        code = "0x6080" + "4f1ef286" + "6040"
        finding = self.check.run(make_ctx(code=code))
        assert finding is not None
        assert "selector 4f1ef286" in finding.description

    def test_detects_set_implementation_selector_in_bytecode(self):
        code = "0x6080" + "a3b2b1fe" + "6040"
        finding = self.check.run(make_ctx(code=code))
        assert finding is not None

    def test_returns_none_for_clean_contract(self):
        code = "0x6080604052604052"
        finding = self.check.run(make_ctx(code=code, abi="[]"))
        assert finding is None

    def test_returns_none_when_no_data(self):
        finding = self.check.run(make_ctx(code="0x", abi="[]"))
        assert finding is None

    def test_does_not_flag_transfer(self):
        abi = json.dumps([
            {"type": "function", "name": "transfer", "inputs": [{"type": "address"}, {"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is None
