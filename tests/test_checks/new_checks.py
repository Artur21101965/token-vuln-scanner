import json
import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.burn import PublicBurnCheck
from src.scanners.checks.evm.permit import PermitCheck
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


class TestPublicBurnCheck:
    check = PublicBurnCheck()

    def test_name_and_severity(self):
        assert self.check.name == "public_burn"
        assert self.check.severity == Severity.HIGH

    def test_detects_burn_in_abi(self):
        abi = json.dumps([
            {"type": "function", "name": "burn", "inputs": [{"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None
        assert "burn" in finding.description.lower()

    def test_detects_burn_from_in_abi(self):
        abi = json.dumps([
            {"type": "function", "name": "burnFrom", "inputs": [{"type": "address"}, {"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None
        assert "burnFrom" in finding.description

    def test_detects_burn_selector_in_bytecode(self):
        code = "0x6080" + "42966c68" + "6040"
        finding = self.check.run(make_ctx(code=code))
        assert finding is not None
        assert "selector 42966c68" in finding.description

    def test_detects_burn_from_selector_in_bytecode(self):
        code = "0x6080" + "79cc6790" + "6040"
        finding = self.check.run(make_ctx(code=code))
        assert finding is not None
        assert "selector 79cc6790" in finding.description

    def test_returns_none_for_clean_contract(self):
        code = "0x6080604052604052"
        finding = self.check.run(make_ctx(code=code, abi="[]"))
        assert finding is None

    def test_returns_none_when_no_data(self):
        finding = self.check.run(make_ctx(code="0x", abi="[]"))
        assert finding is None

    def test_skips_irrelevant_selector(self):
        code = "0x6080" + "a9059cbb" + "6040"
        finding = self.check.run(make_ctx(code=code, abi="[]"))
        assert finding is None

    def test_detects_burn_via_abi_ignoring_case(self):
        abi = json.dumps([
            {"type": "function", "name": "Burn", "inputs": [{"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_does_not_flag_burn_like_names(self):
        abi = json.dumps([
            {"type": "function", "name": "burnish", "inputs": []},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is None


class TestPermitCheck:
    check = PermitCheck()

    def test_name_and_severity(self):
        assert self.check.name == "permit_detected"
        assert self.check.severity == Severity.MEDIUM

    def test_detects_permit_in_abi(self):
        abi = json.dumps([
            {
                "type": "function", "name": "permit",
                "inputs": [
                    {"type": "address"}, {"type": "address"}, {"type": "uint256"},
                    {"type": "uint256"}, {"type": "uint8"}, {"type": "bytes32"},
                    {"type": "bytes32"},
                ],
            },
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None
        assert "permit" in finding.description.lower()

    def test_detects_permit_selector_in_bytecode(self):
        code = "0x6080" + "d505accf" + "6040"
        finding = self.check.run(make_ctx(code=code))
        assert finding is not None

    def test_returns_none_for_clean_contract(self):
        code = "0x6080604052604052"
        finding = self.check.run(make_ctx(code=code, abi="[]"))
        assert finding is None

    def test_returns_none_when_no_data(self):
        finding = self.check.run(make_ctx(code="0x", abi="[]"))
        assert finding is None

    def test_does_not_flag_non_permit_name(self):
        abi = json.dumps([
            {"type": "function", "name": "permanent", "inputs": []},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is None

    def test_detects_permit_in_abi_with_extra_inputs(self):
        abi = json.dumps([
            {
                "type": "function", "name": "permit",
                "inputs": [
                    {"type": "address"}, {"type": "address"}, {"type": "uint256"},
                    {"type": "uint256"}, {"type": "uint256"}, {"type": "uint8"},
                    {"type": "bytes32"}, {"type": "bytes32"},
                ],
            },
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None
