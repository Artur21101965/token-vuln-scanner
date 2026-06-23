import pytest
from unittest.mock import Mock
from src.scanners.checks.evm.hidden import HiddenSelfdestructCheck
from src.scanners.checks.evm.ownership_transfer import OwnershipTransferCheck
from src.scanners.checks.evm.tax_update import TaxUpdateCheck
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
        pool=PoolInfo(address="0xpool", dex="U", liquidity_usd=1000),
        data_collector=dc,
        rpc=Mock(spec=RpcClient),
    )


class TestSelfdestructCheck:
    check = HiddenSelfdestructCheck()

    def test_detects_source_selfdestruct(self):
        finding = self.check.run(make_ctx(code="0x6080selfdestruct6040"))
        assert finding is not None
        assert "selfdestruct" in finding.description.lower()

    def test_bytecode_only_ff_returns_none(self):
        code = "0x6080" + "ff" + "6040"
        finding = self.check.run(make_ctx(code=code))
        assert finding is None

    def test_returns_none_for_clean_bytecode(self):
        finding = self.check.run(make_ctx(code="0x" + "00" * 500))
        assert finding is None

    def test_returns_none_when_no_code(self):
        finding = self.check.run(make_ctx(code="0x"))
        assert finding is None

    def test_does_not_flag_random_ff_in_metadata(self):
        code = "0x6080604052604052"
        finding = self.check.run(make_ctx(code=code))
        assert finding is None


class TestOwnershipTransferCheck:
    check = OwnershipTransferCheck()

    def test_name_and_severity(self):
        assert self.check.name == "public_ownership_transfer"
        assert self.check.severity == Severity.CRITICAL

    def test_detects_transfer_ownership_in_abi(self):
        import json
        abi = json.dumps([
            {"type": "function", "name": "transferOwnership", "inputs": [{"type": "address"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None
        assert "transferOwnership" in finding.description

    def test_detects_set_owner_in_abi(self):
        import json
        abi = json.dumps([
            {"type": "function", "name": "setOwner", "inputs": [{"type": "address"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_detects_change_owner_in_abi(self):
        import json
        abi = json.dumps([
            {"type": "function", "name": "changeOwner", "inputs": [{"type": "address"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_detects_ownership_selector_in_bytecode(self):
        code = "0x6080" + "aae7857b" + "6040"
        finding = self.check.run(make_ctx(code=code))
        assert finding is not None
        assert "aae7857b" in finding.description

    def test_does_not_flag_irrelevant_functions(self):
        import json
        abi = json.dumps([
            {"type": "function", "name": "transfer", "inputs": [{"type": "address"}, {"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is None

    def test_returns_none_for_clean_contract(self):
        finding = self.check.run(make_ctx(code="0x" + "00" * 200))
        assert finding is None


class TestTaxUpdateCheck:
    check = TaxUpdateCheck()

    def test_name_and_severity(self):
        assert self.check.name == "public_tax_update"
        assert self.check.severity == Severity.HIGH

    def test_detects_set_tax_in_abi(self):
        import json
        abi = json.dumps([
            {"type": "function", "name": "setTax", "inputs": [{"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_detects_update_fee_in_abi(self):
        import json
        abi = json.dumps([
            {"type": "function", "name": "updateFee", "inputs": [{"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_detects_set_buy_fee_in_abi(self):
        import json
        abi = json.dumps([
            {"type": "function", "name": "setBuyFee", "inputs": [{"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_detects_set_sell_fee_in_abi(self):
        import json
        abi = json.dumps([
            {"type": "function", "name": "setSellFee", "inputs": [{"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_detects_set_fee_abi(self):
        import json
        abi = json.dumps([
            {"type": "function", "name": "setFeeBps", "inputs": [{"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is not None

    def test_does_not_flag_transfer(self):
        import json
        abi = json.dumps([
            {"type": "function", "name": "transfer", "inputs": [{"type": "address"}, {"type": "uint256"}]},
        ])
        finding = self.check.run(make_ctx(abi=abi))
        assert finding is None

    def test_returns_none_for_clean_contract(self):
        finding = self.check.run(make_ctx(code="0x" + "00" * 200))
        assert finding is None
