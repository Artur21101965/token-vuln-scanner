import pytest
from unittest.mock import Mock
from src.analyzer import Analyzer
from src.types import TokenInfo, PoolInfo, Chain


@pytest.fixture
def mock_queue():
    q = Mock()
    from src.db.queue import PendingToken
    t = PendingToken(row_id=1, chain=Chain.ETHEREUM, token_address="0xabc",
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
        summary="✅ No vulnerabilities found",
    )
    return s


def test_analyzer_processes_token(mock_queue, mock_evm_scanner):
    reporter = Mock()
    analyzer = Analyzer(
        queue=mock_queue,
        scanners={Chain.ETHEREUM: mock_evm_scanner, Chain.SOLANA: Mock()},
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
        scanners={Chain.ETHEREUM: failing_scanner, Chain.SOLANA: Mock()},
        reporter=reporter,
    )
    analyzer.process_one()
    mock_queue.mark_failed.assert_called_once()


def test_analyzer_skips_when_no_tokens():
    mock_queue = Mock()
    mock_queue.claim_next.return_value = None
    analyzer = Analyzer(
        queue=mock_queue,
        scanners={Chain.ETHEREUM: Mock()},
        reporter=Mock(),
    )
    result = analyzer.process_one()
    assert result is False


def test_analyzer_enqueues_deployer_tokens_on_critical():
    from src.db.queue import PendingToken
    from src.abi_resolver import AbiResolver
    q = Mock()
    q.claim_next.return_value = PendingToken(
        row_id=1, chain=Chain.ETHEREUM, token_address="0xabc",
        pair_address="0xpool", symbol="TEST", liquidity_usd=5000, dex="Uniswap"
    )

    scanner = Mock()
    critical_report = Mock(
        token=TokenInfo(address="0xabc", symbol="TEST", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
        findings=[Mock(check_name="public_ownership_transfer", severity=4)],
        summary="⚠️ CRITICAL=1",
    )
    scanner.scan.return_value = critical_report
    scanner._data.get_creator_address.return_value = "0xdeployer"

    resolver = Mock(spec=AbiResolver)
    resolver.fetch_created_contracts.return_value = ["0xtoken2", "0xtoken3"]

    from src.db.deployer_store import DeployerStore

    dstore = Mock(spec=DeployerStore)

    analyzer = Analyzer(
        queue=q,
        scanners={Chain.ETHEREUM: scanner, Chain.SOLANA: Mock()},
        reporter=Mock(),
        deployer_store=dstore,
        abi_resolver=resolver,
    )
    analyzer.process_one()

    assert q.add.call_count >= 2
    added_addrs = [call[1]["token_address"] for call in q.add.call_args_list]
    assert "0xtoken2" in added_addrs
    assert "0xtoken3" in added_addrs

def test_analyzer_does_not_cluster_on_no_critical():
    from src.db.queue import PendingToken
    from src.abi_resolver import AbiResolver
    from src.db.deployer_store import DeployerStore
    q = Mock()
    q.claim_next.return_value = PendingToken(
        row_id=1, chain=Chain.ETHEREUM, token_address="0xabc",
        pair_address="0xpool", symbol="TEST", liquidity_usd=5000, dex="Uniswap"
    )

    scanner = Mock()
    safe_report = Mock(
        token=TokenInfo(address="0xabc", symbol="TEST", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
        findings=[Mock(check_name="low_risk", severity=1)],
        summary="✅ No vulnerabilities found",
    )
    scanner.scan.return_value = safe_report
    scanner._data.get_creator_address.return_value = "0xdeployer"

    resolver = Mock(spec=AbiResolver)
    dstore = Mock(spec=DeployerStore)

    analyzer = Analyzer(
        queue=q,
        scanners={Chain.ETHEREUM: scanner, Chain.SOLANA: Mock()},
        reporter=Mock(),
        deployer_store=dstore,
        abi_resolver=resolver,
    )
    analyzer.process_one()
    resolver.fetch_created_contracts.assert_not_called()

def test_analyzer_selects_solana_scanner():
    from src.db.queue import PendingToken
    q = Mock()
    q.claim_next.return_value = PendingToken(
        row_id=2, chain=Chain.SOLANA, token_address="tokenaddr",
        pair_address="pooladdr", symbol="SOLT", liquidity_usd=5000, dex="Raydium"
    )
    sol_scanner = Mock()
    sol_scanner.scan.return_value = Mock(
        token=TokenInfo(address="tokenaddr", symbol="SOLT", chain=Chain.SOLANA),
        pool=PoolInfo(address="pooladdr", dex="Raydium", liquidity_usd=5000),
        findings=[],
        summary="✅ No vulnerabilities found",
    )
    reporter = Mock()
    analyzer = Analyzer(
        queue=q,
        scanners={Chain.SOLANA: sol_scanner},
        reporter=reporter,
    )
    analyzer.process_one()
    sol_scanner.scan.assert_called_once()
