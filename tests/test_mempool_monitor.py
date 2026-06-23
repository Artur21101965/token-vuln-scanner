import time
import pytest
from unittest.mock import Mock, patch, ANY
from src.types import Chain
from src.monitors.mempool_monitor import MempoolMonitor, DANGEROUS_SELECTORS
from src.rpc import RpcClient


SAMPLE_PENDING_BLOCK = {
    "hash": "0xabcd",
    "transactions": [
        {
            "hash": "0xdeadbeef",
            "from": "0xaaaa",
            "to": "0xdef1abc123456789012345678901234567890123",
            "input": "0x" + "f2fde38b" + "0" * 64,
            "value": "0x0",
            "gas": "0x5208",
        }
    ]
}


class TestMempoolMonitor:
    def test_init(self):
        rpc = Mock(spec=RpcClient)
        m = MempoolMonitor(rpc=rpc, chain=Chain.ETHEREUM)
        assert m._chain == Chain.ETHEREUM
        assert len(m._known_tokens) == 0

    def test_dangerous_selectors_populated(self):
        assert "f2fde38b" in DANGEROUS_SELECTORS
        assert "8129fc1c" in DANGEROUS_SELECTORS
        assert "3659cfe6" in DANGEROUS_SELECTORS
        assert "40c10f19" in DANGEROUS_SELECTORS

    def test_poll_no_tokens_returns_0(self):
        rpc = Mock(spec=RpcClient)
        m = MempoolMonitor(rpc=rpc, chain=Chain.ETHEREUM)
        m._last_refresh = time.time() + 999  # skip token refresh
        assert m.poll() == 0

    def test_poll_known_token_suspicious_tx(self):
        rpc = Mock(spec=RpcClient)
        rpc.call.return_value = SAMPLE_PENDING_BLOCK

        m = MempoolMonitor(rpc=rpc, chain=Chain.ETHEREUM)
        m._last_refresh = time.time() + 999
        m._known_tokens.add("0xdef1abc123456789012345678901234567890123")
        assert m.poll() == 1
        # same block hash — 0
        assert m.poll() == 0

    def test_poll_unknown_token_skipped(self):
        rpc = Mock(spec=RpcClient)
        rpc.call.return_value = SAMPLE_PENDING_BLOCK

        m = MempoolMonitor(rpc=rpc, chain=Chain.ETHEREUM)
        m._last_refresh = time.time() + 999
        m._known_tokens.add("0x9999999999999999999999999999999999999999")
        assert m.poll() == 0

    def test_poll_safe_selector_skipped(self):
        rpc = Mock(spec=RpcClient)
        rpc.call.return_value = {
            "hash": "0xabcd",
            "transactions": [
                {
                    "hash": "0xdeadbeef",
                    "from": "0xaaaa",
                    "to": "0xdef1abc123456789012345678901234567890123",
                    "input": "0xa9059cbb" + "0" * 64,  # transfer() — safe
                    "value": "0x0",
                    "gas": "0x5208",
                }
            ]
        }
        m = MempoolMonitor(rpc=rpc, chain=Chain.ETHEREUM)
        m._last_refresh = time.time() + 999
        m._known_tokens.add("0xdef1abc123456789012345678901234567890123")
        assert m.poll() == 0

    def test_poll_rpc_error_returns_0(self):
        rpc = Mock(spec=RpcClient)
        rpc.call.side_effect = RuntimeError("connection failed")

        m = MempoolMonitor(rpc=rpc, chain=Chain.ETHEREUM)
        m._last_refresh = time.time() + 999
        m._known_tokens.add("0xabc")
        assert m.poll() == 0

    def test_poll_new_block_replaces_old(self):
        rpc = Mock(spec=RpcClient)
        rpc.call.side_effect = [
            SAMPLE_PENDING_BLOCK,
            {**SAMPLE_PENDING_BLOCK, "hash": "0xnewblock",
             "transactions": [{
                 "hash": "0xnewtx",
                 "from": "0xbbbb",
                 "to": "0xdef1abc123456789012345678901234567890123",
                 "input": "0x" + "40c10f19" + "0" * 64 + "0" * 64,
                 "value": "0x0",
                 "gas": "0x5208",
             }]},
        ]
        m = MempoolMonitor(rpc=rpc, chain=Chain.ETHEREUM)
        m._last_refresh = time.time() + 999
        m._known_tokens.add("0xdef1abc123456789012345678901234567890123")
        assert m.poll() == 1  # first tx
        assert m.poll() == 1  # new block hash, new tx hash → also alerted

    def test_poll_no_input_data(self):
        rpc = Mock(spec=RpcClient)
        rpc.call.return_value = {
            "hash": "0xabcd",
            "transactions": [
                {
                    "hash": "0xdeadbeef",
                    "from": "0xaaaa",
                    "to": "0xdef1abc123456789012345678901234567890123",
                    "input": "0x",
                    "value": "0x0",
                }
            ]
        }
        m = MempoolMonitor(rpc=rpc, chain=Chain.ETHEREUM)
        m._last_refresh = time.time() + 999
        m._known_tokens.add("0xdef1abc123456789012345678901234567890123")
        assert m.poll() == 0

    def test_poll_known_contract_skipped(self):
        weth = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
        rpc = Mock(spec=RpcClient)
        rpc.call.return_value = {
            "hash": "0xabcd",
            "transactions": [
                {
                    "hash": "0xdeadbeef",
                    "from": "0xaaaa",
                    "to": weth,
                    "input": "0x" + "f2fde38b" + "0" * 64,
                    "value": "0x0",
                    "gas": "0x5208",
                }
            ]
        }
        m = MempoolMonitor(rpc=rpc, chain=Chain.ETHEREUM)
        m._last_refresh = time.time() + 999
        m._known_tokens.add(weth)
        assert m.poll() == 0

    def test_poll_known_contract_other_chain_not_skipped(self):
        rpc = Mock(spec=RpcClient)
        rpc.call.return_value = {
            "hash": "0xabcd",
            "transactions": [
                {
                    "hash": "0xdeadbeef",
                    "from": "0xaaaa",
                    "to": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                    "input": "0x" + "f2fde38b" + "0" * 64,
                    "value": "0x0",
                    "gas": "0x5208",
                }
            ]
        }
        m = MempoolMonitor(rpc=rpc, chain=Chain.BSC)
        m._last_refresh = time.time() + 999
        m._known_tokens.add("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
        assert m.poll() == 1

    def test_refresh_tokens_loads_from_reports(self, tmp_path):
        rpc = Mock(spec=RpcClient)
        m = MempoolMonitor(rpc=rpc, chain=Chain.ETHEREUM)

        # Create a fake report
        addr = "0xabc123456789012345678901234567890abcdef"
        report_dir = tmp_path / "reports" / "ethereum" / addr
        report_dir.mkdir(parents=True)
        (report_dir / "report.json").write_text('{"test": true}')

        with patch("src.monitors.mempool_monitor.REPORTS_DIR", str(tmp_path / "reports")):
            m.refresh_tokens()
            assert addr.lower() in m._known_tokens
