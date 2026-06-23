import json
import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.withdraw import WithdrawCheck
from src.scanners.checks.evm.approve_all import ApproveAllCheck
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


class TestWithdrawCheck:
    check = WithdrawCheck()

    def test_name_and_severity(self):
        assert self.check.name == "unprotected_withdraw"
        assert self.check.severity == Severity.CRITICAL

    def test_detects_withdraw_in_abi(self):
        abi = json.dumps([
            {"type": "function", "name": "withdraw", "inputs": [{"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None
        assert "withdraw" in finding.description.lower()

    def test_detects_sweep_in_abi(self):
        abi = json.dumps([
            {"type": "function", "name": "sweep", "inputs": [{"type": "address"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_detects_drain_in_abi(self):
        abi = json.dumps([
            {"type": "function", "name": "drain", "inputs": []},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_detects_emergency_withdraw_in_abi(self):
        abi = json.dumps([
            {"type": "function", "name": "emergencyWithdraw", "inputs": [{"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_detects_withdraw_selector_in_bytecode(self):
        code = "0x6080" + "2e1a7d4d" + "6040"
        finding = self.check.run(make_ctx(code=code))
        assert finding is not None
        assert "selector 2e1a7d4d" in finding.description

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

    def test_detects_withdraw_ignoring_case(self):
        abi = json.dumps([
            {"type": "function", "name": "Withdraw", "inputs": [{"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None


class TestApproveAllCheck:
    check = ApproveAllCheck()

    def test_name_and_severity(self):
        assert self.check.name == "unprotected_approve_all"
        assert self.check.severity == Severity.HIGH

    def test_detects_approve_everyone_in_abi(self):
        abi = json.dumps([
            {"type": "function", "name": "approveEveryone", "inputs": [{"type": "address"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_detects_approve_all_in_abi(self):
        abi = json.dumps([
            {"type": "function", "name": "approveAll", "inputs": []},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_detects_dangerous_approve_selector_in_bytecode(self):
        code = "0x6080" + "da682aeb" + "6040"
        finding = self.check.run(make_ctx(code=code))
        assert finding is not None
        assert "selector da682aeb" in finding.description

    def test_does_not_flag_standard_erc20_approve(self):
        abi = json.dumps([
            {"type": "function", "name": "approve", "inputs": [{"type": "address"}, {"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is None

    def test_returns_none_for_clean_contract(self):
        code = "0x6080604052604052"
        finding = self.check.run(make_ctx(code=code, abi="[]"))
        assert finding is None

    def test_returns_none_when_no_data(self):
        finding = self.check.run(make_ctx(code="0x", abi="[]"))
        assert finding is None
