import pytest
from unittest.mock import Mock
from src.types import Chain
from src.rpc import RpcClient


def test_stale_source_checks_balance():
    from src.sources.stale import StaleContractSource
    rpc = Mock(spec=RpcClient)
    rpc.eth_get_balance.return_value = hex(10 ** 18)
    source = StaleContractSource(rpc)
    result = source.check_balance("0xabc")
    assert result == 10 ** 18
    rpc.eth_get_balance.assert_called_once_with("0xabc")
