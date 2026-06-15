import json
from decimal import Decimal
from unittest.mock import MagicMock

import pytest

from src.monitor import DexScreenerMonitor
from src.types import Chain


def make_pair(**overrides):
    data = {
        "chainId": "ethereum",
        "baseToken": {"address": "0x123", "symbol": "TEST"},
        "pairAddress": "0xpair",
        "dexId": "uniswap",
        "liquidity": {"usd": 1000.0},
    }
    data.update(overrides)
    return data


class TestParsePair:
    def test_returns_token_for_supported_chain(self):
        msg = make_pair()
        monitor = DexScreenerMonitor(queue=MagicMock())
        token = monitor._parse_pair(msg)

        assert token is not None
        assert token.chain == "ethereum"
        assert token.token_address == "0x123"
        assert token.pair_address == "0xpair"
        assert token.symbol == "TEST"
        assert token.liquidity_usd == 1000.0
        assert token.dex == "uniswap"

    def test_returns_none_for_unsupported_chain(self):
        msg = make_pair(chainId="polygon")
        monitor = DexScreenerMonitor(queue=MagicMock())
        assert monitor._parse_pair(msg) is None

    def test_returns_none_for_missing_token_address(self):
        msg = make_pair(baseToken={"address": ""})
        monitor = DexScreenerMonitor(queue=MagicMock())
        assert monitor._parse_pair(msg) is None


class TestFilterByLiquidity:
    def test_returns_true_for_above_threshold(self):
        monitor = DexScreenerMonitor(queue=MagicMock(), min_liquidity=500)
        from types import SimpleNamespace
        assert monitor._filter_by_liquidity(SimpleNamespace(liquidity_usd=1000.0)) is True

    def test_returns_true_for_equal_threshold(self):
        monitor = DexScreenerMonitor(queue=MagicMock(), min_liquidity=500)
        from types import SimpleNamespace
        assert monitor._filter_by_liquidity(SimpleNamespace(liquidity_usd=500.0)) is True

    def test_returns_false_for_below_threshold(self):
        monitor = DexScreenerMonitor(queue=MagicMock(), min_liquidity=500)
        from types import SimpleNamespace
        assert monitor._filter_by_liquidity(SimpleNamespace(liquidity_usd=100.0)) is False


class TestProcessMessage:
    def test_calls_queue_add_for_valid_pair(self):
        queue = MagicMock()
        monitor = DexScreenerMonitor(queue=queue, min_liquidity=500)

        msg = make_pair(liquidity={"usd": 1000.0})
        monitor._process_message(json.dumps(msg))

        queue.add.assert_called_once_with(
            chain=Chain.ETHEREUM,
            token_address="0x123",
            pair_address="0xpair",
            symbol="TEST",
            liquidity_usd=Decimal("1000.0"),
            dex="uniswap",
        )

    def test_skips_pair_below_threshold(self):
        queue = MagicMock()
        monitor = DexScreenerMonitor(queue=queue, min_liquidity=500)

        msg = make_pair(liquidity={"usd": 100.0})
        monitor._process_message(json.dumps(msg))

        queue.add.assert_not_called()
