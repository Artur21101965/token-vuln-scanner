"""Tests for signer module — private key loading and address resolution."""

import pytest
from unittest.mock import patch, mock_open
from src.signer import get_receive_address
from src.types import Chain


@patch("src.signer._load_config")
def test_get_receive_address_from_wallet(mock_load):
    """Should prefer wallet address per chain over global receive address."""
    mock_load.return_value = {
        "wallet": {
            "ethereum": "0xwallet_eth",
            "solana": "solana_wallet",
        },
        "executor": {
            "receive_address": "0xglobal_receive",
        },
    }
    addr = get_receive_address(Chain.ETHEREUM)
    assert addr == "0xwallet_eth"

    addr = get_receive_address(Chain.SOLANA)
    assert addr == "solana_wallet"

    addr = get_receive_address(Chain.BSC)
    assert addr == "0xglobal_receive"


@patch("src.signer._load_config")
def test_get_receive_address_empty(mock_load):
    """Should return empty string when nothing configured."""
    mock_load.return_value = {}
    addr = get_receive_address(Chain.ETHEREUM)
    assert addr == ""
