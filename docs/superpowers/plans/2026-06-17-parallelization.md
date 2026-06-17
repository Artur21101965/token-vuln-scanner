# Parallelization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 15-30x scan speedup via RPC caching, parallel checks per token, and parallel token processing

**Architecture:** In-memory dict cache in DataCollector (eliminates ~60% duplicate calls) + ThreadPoolExecutor in BaseScanner (28 checks run in 10 threads instead of sequentially) + worker pool in Analyzer (multiple tokens simultaneously)

**Tech Stack:** Python 3.12, concurrent.futures.ThreadPoolExecutor, SQLite, pytest

---

### Task 1: RPC Cache in DataCollector

**Files:**
- Modify: `src/data.py`
- Test: `tests/test_data.py`

- [ ] **Step 1: Write the failing cache tests**

Add to `tests/test_data.py`:

```python
def test_get_code_cached(collector, mock_rpc):
    mock_rpc.eth_get_code.return_value = "0x1234"
    r1 = collector.get_code("0xabc")
    r2 = collector.get_code("0xabc")
    assert r1 == r2 == "0x1234"
    mock_rpc.eth_get_code.assert_called_once()  # only called once despite 2 calls


def test_get_code_different_addrs_not_cached(collector, mock_rpc):
    mock_rpc.eth_get_code.side_effect = ["0x1234", "0x5678"]
    r1 = collector.get_code("0xabc")
    r2 = collector.get_code("0xdef")
    assert r1 == "0x1234"
    assert r2 == "0x5678"
    assert mock_rpc.eth_get_code.call_count == 2


def test_get_abi_cached(collector, mock_explorer):
    collector.get_abi("0xabc", Chain.ETHEREUM)
    collector.get_abi("0xabc", Chain.ETHEREUM)
    mock_explorer.get_abi.assert_called_once()


def test_cache_clear(collector, mock_rpc):
    mock_rpc.eth_get_code.return_value = "0x1234"
    collector.get_code("0xabc")
    collector.clear_cache()
    collector.get_code("0xabc")
    assert mock_rpc.eth_get_code.call_count == 2  # called again after clear
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_data.py::test_get_code_cached -x -v`
Expected: FAIL (no caching yet)

- [ ] **Step 3: Implement caching in DataCollector**

Modify `src/data.py` to add general-purpose caching:

```python
from typing import Optional, Callable
from src.types import Chain
from src.rpc import RpcClient
from src.explorer import ExplorerClient


class DataCollector:
    def __init__(self, rpc: RpcClient, explorer: ExplorerClient):
        self._rpc = rpc
        self._explorer = explorer
        self._cache: dict[str, str] = {}

    def _cached(self, key: str, fetcher: Callable[[], str]) -> str:
        if key not in self._cache:
            self._cache[key] = fetcher()
        return self._cache[key]

    def _cached_opt(self, key: str, fetcher: Callable[[], Optional[str]]) -> Optional[str]:
        if key not in self._cache:
            result = fetcher()
            self._cache[key] = result if result is not None else ""
        val = self._cache[key]
        return val if val else None

    def clear_cache(self):
        self._cache.clear()

    def get_storage_at(self, address: str, slot: int, block: str = "latest") -> str:
        return self._rpc.get_storage_at(address, slot, block)

    def call_contract(self, to: str, data: str, chain: Chain, block: str = "latest") -> str:
        return self._rpc.eth_call(to, data, block)

    def get_code(self, address: str, block: str = "latest") -> str:
        return self._cached(f"code:{address}:{block}",
            lambda: self._rpc.eth_get_code(address, block))

    def get_abi(self, address: str, chain: Chain) -> Optional[str]:
        if chain == Chain.SOLANA:
            return None
        return self._cached_opt(f"abi:{address}:{chain.value}",
            lambda: self._explorer.get_abi(address, chain))

    def get_source_code(self, address: str, chain: Chain) -> Optional[str]:
        if chain == Chain.SOLANA:
            return None
        return self._explorer.get_source_code(address, chain)

    def get_creator_address(self, address: str, chain: Chain) -> Optional[str]:
        if chain == Chain.SOLANA:
            return None
        return self._explorer.get_contract_creation(address, chain)

    # ... rest of methods unchanged (get_name, get_decimals, etc.)
    # Only get_code, get_abi are cached
```

Note: Only `get_code` and `get_abi` are cached — they're the heaviest duplicates (~15x and ~10x per scan). `get_creator_address`, `get_source_code` are called once. `get_storage_at`, `call_contract`, `get_name`, `get_decimals`, `get_total_supply`, `get_balance_of` vary per call or are called rarely.

Keep `fallback_detected` as-is (not cached — only called once).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_data.py -x -v`
Expected: All tests pass (old + 4 new)

- [ ] **Step 5: Run full quick suite**

Run: `uv run pytest -x -q`
Expected: All passing

- [ ] **Step 6: Commit**

```bash
git add src/data.py tests/test_data.py
git commit -m "feat: RPC caching in DataCollector (get_code, get_abi)"
```

---

### Task 2: Thread-Safe Batch Queue

**Files:**
- Modify: `src/db/queue.py`
- Test: `tests/test_queue.py`

- [ ] **Step 1: Write failing batch claim tests**

Add to `tests/test_queue.py`:

```python
def test_claim_next_batch_returns_multiple(tmp_path):
    db = tmp_path / "test.db"
    q = TokenQueue(str(db))
    q.init_db()
    for i in range(5):
        q.add(Chain.ETHEREUM, f"0x{i:040x}", "", "T", Decimal("100"), "Uniswap")
    batch = q.claim_next_batch(3)
    assert len(batch) == 3
    assert batch[0].token_address == "0x0000000000000000000000000000000000000000"
    assert batch[1].token_address == "0x0000000000000000000000000000000000000001"


def test_claim_next_batch_less_than_requested(tmp_path):
    db = tmp_path / "test.db"
    q = TokenQueue(str(db))
    q.init_db()
    q.add(Chain.ETHEREUM, "0x" + "0" * 40, "", "T", Decimal("100"), "Uniswap")
    batch = q.claim_next_batch(10)
    assert len(batch) == 1


def test_claim_next_batch_empty(tmp_path):
    db = tmp_path / "test.db"
    q = TokenQueue(str(db))
    q.init_db()
    batch = q.claim_next_batch(5)
    assert batch == []


def test_claim_next_batch_sets_status(tmp_path):
    db = tmp_path / "test.db"
    q = TokenQueue(str(db))
    q.init_db()
    q.add(Chain.ETHEREUM, "0x" + "0" * 40, "", "T", Decimal("100"), "Uniswap")
    batch = q.claim_next_batch(5)
    assert len(batch) == 1
    assert batch[0].status == TokenStatus.ANALYZING
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_queue.py::test_claim_next_batch_returns_multiple -x -v`
Expected: FAIL with "AttributeError: 'TokenQueue' object has no attribute 'claim_next_batch'"

- [ ] **Step 3: Implement claim_next_batch**

Add to `TokenQueue` class in `src/db/queue.py`:

```python
def claim_next_batch(self, n: int) -> list[PendingToken]:
    with self._connect() as conn:
        rows = conn.execute(
            "SELECT row_id, chain, token_address, pair_address, symbol, "
            "liquidity_usd, dex, status, error "
            "FROM pending_tokens WHERE status = ? ORDER BY created_at ASC LIMIT ?",
            (TokenStatus.PENDING.value, n),
        ).fetchall()
        if not rows:
            return []
        ids = [r[0] for r in rows]
        placeholders = ",".join("?" for _ in ids)
        conn.execute(
            f"UPDATE pending_tokens SET status = ? WHERE row_id IN ({placeholders})",
            (TokenStatus.ANALYZING.value, *ids),
        )
        conn.commit()
        return [self._row_to_pending(r) for r in rows]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_queue.py -x -v`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src/db/queue.py tests/test_queue.py
git commit -m "feat: batch claim_next_batch for parallel token processing"
```

---

### Task 3: Parallel Checks via ThreadPoolExecutor in BaseScanner

**Files:**
- Modify: `src/scanners/base.py`
- Modify: `tests/test_evm_scanner.py`

- [ ] **Step 1: Write parallel check tests**

Add to `tests/test_evm_scanner.py`:

```python
def test_parallel_checks_collect_all_findings():
    """All check results are collected when running in parallel."""
    class TestScanner(BaseScanner):
        @property
        def checks(self):
            return [DummyCheck(), DummyCheck()]

    data = Mock()
    data.get_code.return_value = ""
    data.fallback_detected.return_value = False
    scanner = TestScanner(data_collector=data, rpc=Mock())
    token = TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM)
    pool = PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=1000)
    report = scanner.scan(token, pool)
    assert len(report.findings) == 2


def test_parallel_checks_handles_error():
    """One failing check doesn't affect other checks in parallel mode."""
    class FailCheck(BaseCheck):
        @property
        def name(self): return "fail"
        @property
        def severity(self): return Severity.CRITICAL
        @property
        def description(self): return ""
        @property
        def recommendation(self): return ""
        def run(self, ctx): raise ValueError("fail")

    class TestScanner(BaseScanner):
        @property
        def checks(self):
            return [FailCheck(), DummyCheck()]

    data = Mock()
    data.get_code.return_value = ""
    data.fallback_detected.return_value = False
    scanner = TestScanner(data_collector=data, rpc=Mock())
    token = TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM)
    pool = PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=1000)
    report = scanner.scan(token, pool)
    assert len(report.findings) == 2  # error finding + dummy finding
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_evm_scanner.py::test_parallel_checks_collect_all_findings -x -v`
Expected: The "error" findings from existing sequential tests may differ — the point is to confirm that parallel mode collects findings correctly. (The test may or may not fail depending on implementation. If it passes, we can still verify the parallel mode works later.)

- [ ] **Step 3: Implement parallel checks**

Modify `src/scanners/base.py` to replace the for-loop in `scan()` with ThreadPoolExecutor:

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.types import TokenInfo, PoolInfo, Finding, Severity, ScanReport
from src.data import DataCollector
from src.rpc import RpcClient
from src.db.deployer_store import DeployerStore

# ... CheckContext and BaseCheck unchanged ...

class BaseScanner(ABC):
    def __init__(self, data_collector: DataCollector, rpc: RpcClient, deployer_store: Optional[DeployerStore] = None):
        self._data = data_collector
        self._rpc = rpc
        self._deployer_store = deployer_store

    @property
    @abstractmethod
    def checks(self) -> list[BaseCheck]:
        ...

    def scan(self, token: TokenInfo, pool: PoolInfo) -> ScanReport:
        ctx = CheckContext(
            token=token,
            pool=pool,
            data_collector=self._data,
            rpc=self._rpc,
            deployer_store=self._deployer_store,
        )
        bytecode = self._data.get_code(token.address) or ""
        if bytecode:
            from src.evm.dispatch_table import parse_dispatch_table
            selectors, _ = parse_dispatch_table(bytecode)
            ctx.dispatch_selectors = set(selectors.keys())
            ctx.has_fallback = self._data.fallback_detected(token.address)

        findings: list[Finding] = []
        with ThreadPoolExecutor(max_workers=10) as pool:
            fut_to_check = {pool.submit(check.run, ctx): check for check in self.checks}
            for fut in as_completed(fut_to_check):
                check = fut_to_check[fut]
                try:
                    result = fut.result()
                    if result is not None:
                        findings.append(result)
                except Exception as exc:
                    findings.append(Finding(
                        check_name=check.name,
                        severity=Severity.MEDIUM,
                        description=f"Check failed with error: {exc}",
                        recommendation="Manual review recommended",
                    ))

        from src.verifiers.confidence import score_confidence, filter_by_confidence, demote_fallback_findings
        scores = {}
        for f in findings:
            is_selector_based = getattr(f, "_selector_based", False)
            has_dispatch = len(ctx.dispatch_selectors) > 0
            score = score_confidence(
                has_fallback=ctx.has_fallback,
                in_dispatch_table=has_dispatch,
                eth_call_succeeded=True,
                selector_based=is_selector_based,
            )
            scores[id(f)] = score
            f.confidence = score

        findings = demote_fallback_findings(findings, scores)
        findings = filter_by_confidence(findings, scores)
        return ScanReport(token=token, pool=pool, findings=findings)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_evm_scanner.py -x -v`
Expected: All 7 tests pass (3 original + 1 confidence + 3 new)

Run: `uv run pytest -x -q`
Expected: All 342+ tests pass

- [ ] **Step 5: Commit**

```bash
git add src/scanners/base.py tests/test_evm_scanner.py
git commit -m "feat: parallel checks via ThreadPoolExecutor in BaseScanner"
```

---

### Task 4: Worker Pool in Analyzer

**Files:**
- Modify: `src/analyzer.py`
- Test: `tests/test_analyzer.py`

- [ ] **Step 1: Write worker pool tests**

Create `tests/test_analyzer.py`:

```python
from unittest.mock import Mock, patch
from src.analyzer import Analyzer
from src.types import Chain
from decimal import Decimal


def test_analyzer_parallel_scan_limited_by_workers():
    """Max workers limits concurrent token processing."""
    queue = Mock()
    scanner = Mock()
    reporter = Mock()

    analyzer = Analyzer(
        queue=queue,
        scanners={Chain.ETHEREUM: scanner},
        reporter=reporter,
        max_workers=3,
    )
    assert analyzer._max_workers == 3


def test_analyzer_parallel_claims_batch():
    """Analyzer claims token batch based on max_workers."""
    queue = Mock()
    queue.claim_next_batch.return_value = []
    scanner = Mock()
    reporter = Mock()

    analyzer = Analyzer(
        queue=queue,
        scanners={Chain.ETHEREUM: scanner},
        reporter=reporter,
        max_workers=4,
    )
    analyzer.process_batch()
    queue.claim_next_batch.assert_called_once_with(4)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_analyzer.py -x -v`
Expected: FAIL (analyzer has no process_batch or max_workers)

- [ ] **Step 3: Implement parallel token processing**

Modify `src/analyzer.py`:

Add `max_workers` to `__init__`:
```python
class Analyzer:
    def __init__(
        self,
        queue: TokenQueue,
        scanners: dict[Chain, BaseScanner],
        reporter: JsonReporter,
        slot_monitors: Optional[dict[Chain, SlotMonitor]] = None,
        deployer_store: Optional[DeployerStore] = None,
        top_token_scanner: Optional[TopTokenScanner] = None,
        abi_resolver: Optional[AbiResolver] = None,
        max_workers: int = 4,
    ):
        # ... existing init ...
        self._max_workers = max_workers
```

Add `process_batch` method:
```python
from concurrent.futures import ThreadPoolExecutor, as_completed
import concurrent.futures

def process_batch(self) -> int:
    tokens = self._queue.claim_next_batch(self._max_workers)
    if not tokens:
        return 0

    with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
        fut_to_token = {}
        for token in tokens:
            chain = token.chain
            scanner = self._get_scanner(chain)
            if scanner is None:
                self._queue.mark_failed(token.row_id, error=f"No scanner for chain: {chain.name}")
                continue
            fut = pool.submit(self._scan_and_report, token, chain, scanner)
            fut_to_token[fut] = token

        for fut in as_completed(fut_to_token):
            token = fut_to_token[fut]
            try:
                fut.result()
                self._queue.mark_done(token.row_id)
                logger.info("Done %s — batch worker", token.symbol)
            except Exception as exc:
                logger.error("Failed %s: %s", token.symbol, exc)
                self._queue.mark_failed(token.row_id, error=str(exc))

    return len(tokens)
```

Modify `run()` to use `process_batch`:
```python
def run(self, interval: float = 1.0):
    logger.info("Analyzer started (max_workers=%d)", self._max_workers)
    idle_cycles = 0
    while True:
        try:
            count = self.process_batch()
            if count > 0:
                idle_cycles = 0
            else:
                idle_cycles += 1
                if idle_cycles >= 10:
                    self._check_slot_changes()
                    self._rescan_old_tokens()
                    self._scan_top_tokens()
                    idle_cycles = 0
                time.sleep(interval)
        except KeyboardInterrupt:
            break
        except Exception as exc:
            logger.error("Analyzer error: %s", exc)
            time.sleep(5)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_analyzer.py -x -v`
Expected: Both tests pass

Run: `uv run pytest -x -q`
Expected: All passing

- [ ] **Step 5: Update run_analyzer.py to accept max_workers**

Read `run_analyzer.py` and add `max_workers` parameter from env:

```python
import os

max_workers = int(os.environ.get("SCAN_WORKERS", "4"))
analyzer = Analyzer(
    queue=queue,
    scanners=scanners,
    reporter=reporter,
    slot_monitors=slot_monitors,
    deployer_store=deployer_store,
    top_token_scanner=top_token_scanner,
    abi_resolver=abi_resolver,
    max_workers=max_workers,
)
```

- [ ] **Step 6: Commit**

```bash
git add src/analyzer.py tests/test_analyzer.py run_analyzer.py
git commit -m "feat: parallel token processing via worker pool"
```

---

### Task 5: Run Full Test Suite

- [ ] **Step 1: Run all tests**

Run: `uv run pytest -x -q`
Expected: All passing (~345+ tests)

- [ ] **Step 2: Final commit if needed**

```bash
git commit -am "chore: update tests for parallelization"
```

---

## Summary

| Task | What | Files | Est. Speedup |
|------|------|-------|-------------|
| 1 | RPC cache in DataCollector | `data.py` | ~3x |
| 2 | Batch queue claim | `queue.py` | Enabler |
| 3 | Parallel checks (ThreadPool) | `base.py` | ~5-8x |
| 4 | Worker pool (multi-token) | `analyzer.py` | ~4x |
| **Total** | | 5 files | **15-30x** |
