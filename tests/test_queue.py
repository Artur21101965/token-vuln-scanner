from decimal import Decimal
import tempfile
import os

import pytest

from src.types import Chain, TokenStatus, PendingToken
from src.db.queue import TokenQueue


@pytest.fixture
def db_path():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        yield f.name
    os.unlink(f.name)


@pytest.fixture
def queue(db_path):
    q = TokenQueue(db_path=db_path)
    q.init_db()
    return q


def test_add_increases_pending_count(queue):
    queue.add(
        chain=Chain.ETHEREUM,
        token_address="0xabc",
        pair_address="0xpair1",
        symbol="TEST",
        liquidity_usd=Decimal("10000"),
        dex="Uniswap V2",
    )
    assert queue.count_pending() == 1


def test_add_duplicate_is_skipped(queue):
    queue.add(Chain.ETHEREUM, "0xabc", "0xpair1", "TEST", Decimal("10000"), "Uniswap")
    queue.add(Chain.ETHEREUM, "0xabc", "0xpair1", "TEST", Decimal("20000"), "Uniswap")
    assert queue.count_pending() == 1


def test_claim_next_returns_oldest_pending(queue):
    queue.add(Chain.ETHEREUM, "0xa", "0xpa", "A", Decimal("100"), "Dex")
    queue.add(Chain.ETHEREUM, "0xb", "0xpb", "B", Decimal("200"), "Dex")
    first = queue.claim_next()
    second = queue.claim_next()
    assert first is not None
    assert second is not None
    assert first.token_address == "0xa"
    assert second.token_address == "0xb"
    assert first.status == TokenStatus.ANALYZING
    assert second.status == TokenStatus.ANALYZING


def test_claim_next_on_empty_returns_none(queue):
    assert queue.claim_next() is None


def test_mark_done(queue):
    queue.add(Chain.BSC, "0xabc", "0xpair1", "TEST", Decimal("1000"), "PancakeSwap")
    token = queue.claim_next()
    assert token is not None
    queue.mark_done(token.row_id)
    done = queue.get(token.row_id)
    assert done is not None
    assert done.status == TokenStatus.DONE


def test_mark_failed_stores_error(queue):
    queue.add(Chain.SOLANA, "abc123", "pair1", "SOLT", Decimal("500"), "Raydium")
    token = queue.claim_next()
    assert token is not None
    queue.mark_failed(token.row_id, "Simulation failed")
    failed = queue.get(token.row_id)
    assert failed is not None
    assert failed.status == TokenStatus.FAILED
    assert failed.error == "Simulation failed"


def test_count_pending_excludes_non_pending(queue):
    queue.add(Chain.ETHEREUM, "0xa", "0xpa", "A", Decimal("100"), "Dex")
    queue.add(Chain.ETHEREUM, "0xb", "0xpb", "B", Decimal("200"), "Dex")
    queue.add(Chain.ETHEREUM, "0xc", "0xpc", "C", Decimal("300"), "Dex")

    t1 = queue.claim_next()
    t2 = queue.claim_next()
    assert t1 is not None and t2 is not None
    queue.mark_done(t1.row_id)
    queue.mark_failed(t2.row_id, "err")

    assert queue.count_pending() == 1  # only the third remains pending


def test_get_returns_token_by_row_id(queue):
    queue.add(Chain.ETHEREUM, "0xabc", "0xpair1", "TEST", Decimal("1000"), "Uniswap")
    token = queue.claim_next()
    assert token is not None
    fetched = queue.get(token.row_id)
    assert fetched is not None
    assert fetched.token_address == "0xabc"
    assert fetched.symbol == "TEST"
