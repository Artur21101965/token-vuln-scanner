import pytest
from unittest.mock import patch, MagicMock
from src.sources.blockscout import BlockscoutRecentSource, BLOCKSCOUT_URLS
from src.types import Chain



def test_blockscout_urls_defined():
    assert Chain.ETHEREUM in BLOCKSCOUT_URLS
    assert Chain.BSC in BLOCKSCOUT_URLS
    assert Chain.POLYGON in BLOCKSCOUT_URLS
    assert Chain.ARBITRUM in BLOCKSCOUT_URLS
    assert Chain.BASE in BLOCKSCOUT_URLS
    assert Chain.OPTIMISM in BLOCKSCOUT_URLS
    assert Chain.AVALANCHE in BLOCKSCOUT_URLS
    assert Chain.ZKSYNC in BLOCKSCOUT_URLS
    assert Chain.LINEA in BLOCKSCOUT_URLS
    assert Chain.SCROLL in BLOCKSCOUT_URLS


@patch("src.sources.blockscout.httpx.Client")
def test_blockscout_fetch_returns_targets(mock_client_class):
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client_class.return_value = mock_client
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "items": [
            {"address": {"hash": "0x1234567890123456789012345678901234567890"}},
            {"address": {"hash": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"}},
        ]
    }
    mock_client.get.return_value = resp

    source = BlockscoutRecentSource(max_pages=1)
    targets = source.fetch(Chain.ETHEREUM)
    assert len(targets) == 2
    assert targets[0].address == "0x1234567890123456789012345678901234567890"
    assert targets[0].chain == Chain.ETHEREUM
    assert targets[0].source == "blockscout"


@patch("src.sources.blockscout.httpx.Client")
def test_blockscout_fetch_skips_invalid_or_missing_hash(mock_client_class):
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client_class.return_value = mock_client
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "items": [{"address": {}}, {"address": {"hash": "0xabc"}}]
    }
    mock_client.get.return_value = resp

    source = BlockscoutRecentSource(max_pages=1)
    targets = source.fetch(Chain.ETHEREUM)
    assert len(targets) == 1
    assert targets[0].address == "0xabc"


@patch("src.sources.blockscout.httpx.Client")
def test_blockscout_fetch_handles_http_error(mock_client_class):
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client_class.return_value = mock_client
    resp = MagicMock()
    resp.status_code = 500
    mock_client.get.return_value = resp

    source = BlockscoutRecentSource(max_pages=1)
    targets = source.fetch(Chain.ETHEREUM)
    assert len(targets) == 0


@patch("src.sources.blockscout.httpx.Client")
def test_blockscout_fetch_unknown_chain(mock_client_class):
    source = BlockscoutRecentSource()
    targets = source.fetch(Chain.SOLANA)
    assert len(targets) == 0
