import pytest
from unittest.mock import Mock, patch
from src.data import DataCollector
from src.types import Chain


@pytest.fixture
def mock_rpc():
    rpc = Mock()
    rpc.call.return_value = "0x0000000000000000000000000000000000000000000000000000000000000000"
    return rpc


@pytest.fixture
def mock_explorer():
    exp = Mock()
    exp.get_abi.return_value = '[{"type":"function","name":"owner","outputs":[{"type":"address"}]}]'
    exp.get_source_code.return_value = "contract Token { function owner() ... }"
    return exp


@pytest.fixture
def collector(mock_rpc, mock_explorer):
    return DataCollector(rpc=mock_rpc, explorer=mock_explorer)


def test_get_storage_at(collector, mock_rpc):
    collector.get_storage_at("0xabc", 0)
    mock_rpc.call.assert_called_once_with("eth_getStorageAt", ["0xabc", "0x0", "latest"])


def test_get_code(collector, mock_rpc):
    collector.get_code("0xabc")
    mock_rpc.call.assert_called_once_with("eth_getCode", ["0xabc", "latest"])


def test_call_contract(collector, mock_rpc):
    collector.call_contract("0xabc", "0xdeadbeef", Chain.ETHEREUM)
    mock_rpc.call.assert_called_once()


def test_get_abi(collector, mock_explorer):
    abi = collector.get_abi("0xabc", Chain.ETHEREUM)
    assert abi is not None
    mock_explorer.get_abi.assert_called_once_with("0xabc", Chain.ETHEREUM)


def test_get_abi_solana_returns_none(collector):
    abi = collector.get_abi("abc", Chain.SOLANA)
    assert abi is None


def test_get_source_code(collector, mock_explorer):
    src = collector.get_source_code("0xabc", Chain.ETHEREUM)
    assert src is not None
    mock_explorer.get_source_code.assert_called_once_with("0xabc", Chain.ETHEREUM)
