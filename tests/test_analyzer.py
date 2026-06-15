import pytest
from unittest.mock import Mock, patch
from src.analyzer import Analyzer
from src.types import TokenInfo, PoolInfo, Chain


@pytest.fixture
def mock_queue():
    q = Mock()
    from src.db.queue import PendingToken
    t = PendingToken(row_id=1, chain="ethereum", token_address="0xabc",
                     pair_address="0xpool", symbol="TEST", liquidity_usd=5000, dex="Uniswap")
    q.claim_next.return_value = t
    return q


@pytest.fixture
def mock_evm_scanner():
    s = Mock()
    s.scan.return_value = Mock(
        token=TokenInfo(address="0xabc", symbol="TEST", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
        findings=[],
        summary="\u2705 No vulnerabilities found",
    )
    return s


def test_analyzer_processes_token(mock_queue, mock_evm_scanner):
    reporter = Mock()
    analyzer = Analyzer(
        queue=mock_queue,
        evm_scanner=mock_evm_scanner,
        solana_scanner=Mock(),
        reporter=reporter,
    )
    result = analyzer.process_one()
    assert result is True
    mock_queue.claim_next.assert_called_once()
    mock_evm_scanner.scan.assert_called_once()
    reporter.write.assert_called_once()
    mock_queue.mark_done.assert_called_once_with(1)


def test_analyzer_marks_failed_on_error(mock_queue):
    reporter = Mock()
    failing_scanner = Mock()
    failing_scanner.scan.side_effect = Exception("RPC error")
    analyzer = Analyzer(
        queue=mock_queue,
        evm_scanner=failing_scanner,
        solana_scanner=Mock(),
        reporter=reporter,
    )
    analyzer.process_one()
    mock_queue.mark_failed.assert_called_once()


def test_analyzer_skips_when_no_tokens():
    mock_queue = Mock()
    mock_queue.claim_next.return_value = None
    analyzer = Analyzer(
        queue=mock_queue,
        evm_scanner=Mock(),
        solana_scanner=Mock(),
        reporter=Mock(),
    )
    result = analyzer.process_one()
    assert result is False


def test_analyzer_selects_solana_scanner():
    from src.db.queue import PendingToken
    q = Mock()
    q.claim_next.return_value = PendingToken(
        row_id=2, chain="solana", token_address="tokenaddr",
        pair_address="pooladdr", symbol="SOLT", liquidity_usd=5000, dex="Raydium"
    )
    sol_scanner = Mock()
    sol_scanner.scan.return_value = Mock(
        token=TokenInfo(address="tokenaddr", symbol="SOLT", chain=Chain.SOLANA),
        pool=PoolInfo(address="pooladdr", dex="Raydium", liquidity_usd=5000),
        findings=[],
        summary="\u2705 No vulnerabilities found",
    )
    reporter = Mock()
    analyzer = Analyzer(
        queue=q,
        evm_scanner=Mock(),
        solana_scanner=sol_scanner,
        reporter=reporter,
    )
    analyzer.process_one()
    sol_scanner.scan.assert_called_once()
