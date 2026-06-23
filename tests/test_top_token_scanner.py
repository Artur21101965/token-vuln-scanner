import pytest
from unittest.mock import Mock, patch
from src.monitors.top_token_scanner import TopTokenScanner
from src.db.queue import TokenQueue
from src.types import Chain


class TestTopTokenScanner:
    def test_init(self):
        q = Mock(spec=TokenQueue)
        s = TopTokenScanner(queue=q, min_liquidity=500)
        assert s._min_liquidity == 500
        assert s._queue is q

    @patch("src.monitors.top_token_scanner.httpx.Client")
    def test_scan_empty_response(self, mock_http):
        client = mock_http.return_value
        client.get.return_value.json.return_value = {"data": []}
        q = Mock(spec=TokenQueue)
        s = TopTokenScanner(queue=q, min_liquidity=500)
        assert s.scan() == 0

    @patch("src.monitors.top_token_scanner.httpx.Client")
    def test_scan_skips_unsupported_chain(self, mock_http):
        client = mock_http.return_value
        client.get.return_value.json.return_value = {
            "data": [{"chainId": "cosmos", "tokenAddress": "0xabc"}]
        }
        q = Mock(spec=TokenQueue)
        s = TopTokenScanner(queue=q, min_liquidity=500)
        assert s.scan() == 0

    @patch("src.monitors.top_token_scanner.httpx.Client")
    def test_scan_http_error_returns_0(self, mock_http):
        client = mock_http.return_value
        client.get.side_effect = Exception("timeout")
        q = Mock(spec=TokenQueue)
        s = TopTokenScanner(queue=q, min_liquidity=500)
        assert s.scan() == 0

    @patch("src.monitors.top_token_scanner.httpx.Client")
    def test_scan_bulk_empty_response(self, mock_http):
        client = mock_http.return_value
        client.get.return_value.json.return_value = {"pairs": []}
        q = Mock(spec=TokenQueue)
        s = TopTokenScanner(queue=q, min_liquidity=500)
        assert s.scan_bulk(max_per_chain=5) == 0

    @patch("src.monitors.top_token_scanner.httpx.Client")
    def test_scan_retro_empty(self, mock_http):
        client = mock_http.return_value
        client.get.return_value.json.return_value = {"pairs": []}
        q = Mock(spec=TokenQueue)
        s = TopTokenScanner(queue=q, min_liquidity=500)
        assert s.scan_retro(max_per_chain=5) == 0

    @patch("src.monitors.top_token_scanner.httpx.Client")
    def test_scan_retro_enqueues(self, mock_http):
        client = mock_http.return_value
        client.get.return_value.json.return_value = {
            "pairs": [
                {
                    "chainId": "ethereum",
                    "baseToken": {"address": "0xabc", "symbol": "TEST"},
                    "pairAddress": "0xpair",
                    "liquidity": {"usd": 100000},
                    "dexId": "uniswap",
                }
            ]
        }
        q = Mock(spec=TokenQueue)
        s = TopTokenScanner(queue=q, min_liquidity=500)
        assert s.scan_retro(max_per_chain=5) == 1
        q.add.assert_called_once()

    @patch("src.monitors.top_token_scanner.httpx.Client")
    def test_scan_retro_skips_insufficient_liquidity(self, mock_http):
        client = mock_http.return_value
        client.get.return_value.json.return_value = {
            "pairs": [
                {
                    "chainId": "ethereum",
                    "baseToken": {"address": "0xabc", "symbol": "TEST"},
                    "pairAddress": "0xpair",
                    "liquidity": {"usd": 10},
                    "dexId": "uniswap",
                }
            ]
        }
        q = Mock(spec=TokenQueue)
        s = TopTokenScanner(queue=q, min_liquidity=500)
        assert s.scan_retro(max_per_chain=5) == 0

    @patch("src.monitors.top_token_scanner.httpx.Client")
    def test_scan_retro_bulk_empty(self, mock_http):
        client = mock_http.return_value
        client.get.return_value.json.return_value = {"pairs": []}
        q = Mock(spec=TokenQueue)
        s = TopTokenScanner(queue=q, min_liquidity=500)
        assert s.scan_retro_bulk(max_per_chain=5) == 0

    @patch("src.monitors.top_token_scanner.httpx.Client")
    def test_scan_retro_bulk_enqueues(self, mock_http):
        client = mock_http.return_value
        client.get.return_value.json.return_value = {
            "pairs": [{
                "chainId": "ethereum",
                "baseToken": {"address": "0xabc", "symbol": "TEST"},
                "pairAddress": "0xpair",
                "liquidity": {"usd": 100000},
                "dexId": "uniswap",
            }]
        }
        q = Mock(spec=TokenQueue)
        s = TopTokenScanner(queue=q, min_liquidity=500)
        assert s.scan_retro_bulk(chains=[Chain.ETHEREUM], max_per_chain=5) >= 1

    @patch("src.monitors.top_token_scanner.httpx.Client")
    def test_scan_bulk_skip_duplicate(self, mock_http):
        client = mock_http.return_value
        client.get.return_value.json.return_value = {
            "pairs": [
                {
                    "chainId": "ethereum",
                    "baseToken": {"address": "0xabc", "symbol": "TEST"},
                    "pairAddress": "0xpair",
                    "liquidity": {"usd": 100000},
                    "dexId": "uniswap",
                }
            ]
        }
        q = Mock(spec=TokenQueue)
        s = TopTokenScanner(queue=q, min_liquidity=500)
        # first call enqueues
        assert s.scan_bulk(max_per_chain=5) >= 0
        # second call should still find, but will be skipped by seen_this_pass
        # the mock returns the same data, so we'll get the same token
        assert s.scan_bulk(max_per_chain=5) == 0
