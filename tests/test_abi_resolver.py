import pytest
from unittest.mock import Mock, patch
from src.types import Finding, Severity, TokenInfo, PoolInfo, Chain
from src.scanners.base import CheckContext
from src.verifiers.exploit_simulator import SimulatedExploitVerifier, SELECTOR_CALLDATA
from src.data import DataCollector
from src.rpc import RpcClient
from src.abi_resolver import AbiResolver, _dummy_value


class TestAbiResolver:
    def test_dummy_value_address(self):
        assert _dummy_value("address") == "0x0000000000000000000000000000000000000002"

    def test_dummy_value_uint(self):
        assert _dummy_value("uint256") == 0
        assert _dummy_value("uint8") == 0

    def test_dummy_value_bool(self):
        assert _dummy_value("bool") is False

    def test_dummy_value_bytes32(self):
        assert _dummy_value("bytes32") == b"\x00" * 32

    def test_dummy_value_string(self):
        assert _dummy_value("string") == ""

    def test_dummy_value_array(self):
        assert _dummy_value("uint256[]") == []

    def test_build_calldata_no_inputs(self):
        r = AbiResolver()
        func = {"name": "initialize", "type": "function", "inputs": []}
        calldata = r.build_calldata(func)
        assert calldata == "8129fc1c"  # keccak("initialize()")[:4]

    def test_build_calldata_address_input(self):
        r = AbiResolver()
        func = {"name": "transferOwnership", "type": "function", "inputs": [{"type": "address", "name": "newOwner"}]}
        calldata = r.build_calldata(func)
        assert calldata.startswith("f2fde38b")
        assert len(calldata) == 8 + 64  # 4-byte selector + 32-byte address
        assert "0000000000000000000000000000000000000002" in calldata

    def test_build_calldata_mint(self):
        r = AbiResolver()
        func = {"name": "mint", "type": "function", "inputs": [{"type": "address", "name": "to"}, {"type": "uint256", "name": "amount"}]}
        calldata = r.build_calldata(func)
        assert calldata.startswith("40c10f19")
        assert "0000000000000000000000000000000000000002" in calldata
        assert "0000000000000000000000000000000000000000000000000000000000000000" in calldata

    def test_get_function_by_selector_cached(self):
        r = AbiResolver()
        abi = [
            {"name": "initialize", "type": "function", "inputs": []},
            {"name": "transferOwnership", "type": "function", "inputs": [{"type": "address", "name": "newOwner"}]},
        ]
        with patch.object(r, 'get_abi', return_value=abi):
            func = r.get_function_by_selector("0xabc", Chain.ETHEREUM, "8129fc1c")
            assert func is not None
            assert func["name"] == "initialize"

            func2 = r.get_function_by_selector("0xabc", Chain.ETHEREUM, "f2fde38b")
            assert func2 is not None
            assert func2["name"] == "transferOwnership"

            # wrong selector
            func3 = r.get_function_by_selector("0xabc", Chain.ETHEREUM, "00000000")
            assert func3 is None

    def test_get_function_by_selector_none_abi(self):
        r = AbiResolver()
        with patch.object(r, 'get_abi', return_value=None):
            func = r.get_function_by_selector("0xabc", Chain.ETHEREUM, "8129fc1c")
            assert func is None

    def test_build_calldata_withdraw(self):
        r = AbiResolver()
        func = {"name": "withdraw", "type": "function", "inputs": [{"type": "uint256", "name": "amount"}]}
        calldata = r.build_calldata(func)
        assert calldata.startswith("2e1a7d4d")
        assert "0000000000000000000000000000000000000000000000000000000000000000" in calldata


class TestExploitSimulatorWithAbi:
    def test_uses_abi_calldata_when_available(self):
        abi = [
            {"name": "initialize", "type": "function", "inputs": []},
        ]
        rpc = Mock(spec=RpcClient)
        rpc.eth_call.side_effect = [
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            "0x",
        ]
        ctx = CheckContext(
            token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
            pool=PoolInfo(address="0xpool", dex="Uniswap V2", liquidity_usd=5000),
            data_collector=Mock(spec=DataCollector),
            rpc=rpc,
        )
        f = Finding(
            check_name="public_ownership_transfer",
            severity=Severity.CRITICAL,
            description="Ownership transfer selector found",
            recommendation="Fix it",
            details={"selector": "f2fde38b"},
        )
        v = SimulatedExploitVerifier()
        with patch.object(v._resolver, 'get_abi', return_value=abi):
            with patch.object(v._resolver, 'get_function_by_selector', return_value=abi[0]):
                result = v.verify(ctx, f)
                assert result.confirmed is True
                assert result.confidence == 0.99

    def test_falls_back_to_hardcoded_when_no_abi(self):
        rpc = Mock(spec=RpcClient)
        rpc.eth_call.side_effect = RuntimeError("reverted")
        ctx = CheckContext(
            token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
            pool=PoolInfo(address="0xpool", dex="Uniswap V2", liquidity_usd=5000),
            data_collector=Mock(spec=DataCollector),
            rpc=rpc,
        )
        f = Finding(
            check_name="unprotected_initialize",
            severity=Severity.CRITICAL,
            description="Initialize selector found",
            recommendation="Fix it",
            details={"selector": "8129fc1c"},
        )
        v = SimulatedExploitVerifier()
        with patch.object(v._resolver, 'get_abi', return_value=None):
            with patch.object(v._resolver, 'get_function_by_selector', return_value=None):
                result = v.verify(ctx, f)
                assert result.confirmed is False  # reverted
                assert result.confidence == 0.85

    def test_unknown_selector_no_abi_fallback(self):
        rpc = Mock(spec=RpcClient)
        ctx = CheckContext(
            token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
            pool=PoolInfo(address="0xpool", dex="Uniswap V2", liquidity_usd=5000),
            data_collector=Mock(spec=DataCollector),
            rpc=rpc,
        )
        f = Finding(
            check_name="unprotected_upgrade",
            severity=Severity.CRITICAL,
            description="Upgrade selector found",
            recommendation="Fix it",
            details={"selector": "aabbccdd"},
        )
        v = SimulatedExploitVerifier()
        with patch.object(v._resolver, 'get_abi', return_value=None):
            with patch.object(v._resolver, 'get_function_by_selector', return_value=None):
                result = v.verify(ctx, f)
                assert result.confirmed is True
                assert result.confidence == 0.3

    def test_fetch_created_contracts_returns_addresses(self):
        r = AbiResolver()
        fake_response = {
            "items": [
                {"created_contract": {"hash": "0xabc"}},
                {"created_contract": {"hash": "0xdef"}},
            ],
            "next_page_params": None,
        }
        with patch.object(r._http, "get") as mock_get:
            mock_get.return_value = Mock(status_code=200)
            mock_get.return_value.json.return_value = fake_response
            result = r.fetch_created_contracts("0xdeployer", Chain.ETHEREUM)
            assert result == ["0xabc", "0xdef"]
            mock_get.assert_called_once_with(
                "https://eth.blockscout.com/api/v2/addresses/0xdeployer/created-contracts",
                timeout=10,
            )

    def test_fetch_created_contracts_error_returns_empty(self):
        r = AbiResolver()
        with patch.object(r._http, "get") as mock_get:
            mock_get.side_effect = RuntimeError("timeout")
            result = r.fetch_created_contracts("0xdeployer", Chain.ETHEREUM)
            assert result == []

    def test_fetch_created_contracts_unknown_chain_returns_empty(self):
        from src.types import Chain
        r = AbiResolver()
        result = r.fetch_created_contracts("0xdeployer", Chain.SOLANA)
        assert result == []

    def test_ownership_transfer_lower_conf_when_renounced(self):
        rpc = Mock(spec=RpcClient)
        # owner() returns zero address
        rpc.eth_call.side_effect = [
            "0x0000000000000000000000000000000000000000000000000000000000000000",  # owner() = 0x0
            "0x",  # transferOwnership succeeds
        ]
        ctx = CheckContext(
            token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
            pool=PoolInfo(address="0xpool", dex="Uniswap V2", liquidity_usd=5000),
            data_collector=Mock(spec=DataCollector),
            rpc=rpc,
        )
        f = Finding(
            check_name="public_ownership_transfer",
            severity=Severity.CRITICAL,
            description="Ownership transfer selector found",
            recommendation="Fix it",
            details={"selector": "f2fde38b"},
        )
        v = SimulatedExploitVerifier()
        result = v.verify(ctx, f)
        assert result.confirmed is True
        assert result.confidence == 0.7  # already renounced

    def test_mint_high_conf_when_balance_zero(self):
        rpc = Mock(spec=RpcClient)
        rpc.eth_call.side_effect = [
            "0x0000000000000000000000000000000000000000000000000000000000000000",  # balanceOf(attacker) = 0
            "0x",  # mint succeeds
        ]
        ctx = CheckContext(
            token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
            pool=PoolInfo(address="0xpool", dex="Uniswap V2", liquidity_usd=5000),
            data_collector=Mock(spec=DataCollector),
            rpc=rpc,
        )
        f = Finding(
            check_name="unprotected_mint",
            severity=Severity.CRITICAL,
            description="Mint selector found",
            recommendation="Fix it",
            details={"selector": "40c10f19"},
        )
        v = SimulatedExploitVerifier()
        result = v.verify(ctx, f)
        assert result.confirmed is True
        assert result.confidence == 0.99
