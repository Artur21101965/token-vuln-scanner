# Parallelization Design

**Date:** 2026-06-17
**Goal:** 15-30x scan speedup via caching, parallel checks, and parallel token processing
**Architecture:** In-memory cache → ThreadPoolExecutor for per-token checks → worker pool for multi-token scanning
**Style:** Incremental — no async rewrite of check files, no behavioral change to checks

---

## Phase 1: RPC Cache in DataCollector

### Problem
- `get_code()` called ~15 times per token per scan — identical RPC call each time
- `get_abi()` called ~10 times
- `eth_blockNumber()` called ~5 times (split across historical/multi_send/sandwich checks)
- No caching anywhere

### Solution
Add `functools.lru_cache` or manual `dict` cache to `DataCollector` methods that return the same result within one scan.

Cache key: `(method_name, address, block)` where block defaults to `"latest"` which is stable within a scan cycle.

```python
class DataCollector:
    def __init__(self, rpc, explorer):
        self._cache: dict[str, str] = {}
    
    def _cached(self, key: str, fetcher) -> str:
        if key not in self._cache:
            self._cache[key] = fetcher()
        return self._cache[key]
    
    def get_code(self, address: str, block: str = "latest") -> str:
        return self._cached(f"code:{address}:{block}", 
            lambda: self._rpc.eth_get_code(address, block))
    
    def get_abi(self, address: str, chain: Chain) -> Optional[str]:
        return self._cached(f"abi:{address}:{chain.value}",
            lambda: self._explorer.get_abi(address, chain))
```

### Impact
- ~60% fewer RPC calls per token
- ~3x speedup
- Zero risk (pure additive change, no behavioral change)
- Files: `src/data.py` only

---

## Phase 2: Parallel Checks via ThreadPoolExecutor

### Problem
- 28 checks run sequentially in a for-loop
- Each check makes 1-10 RPC calls (blocking)
- Total ~50-80 sequential network calls per token at ~100-500ms each = 15-45s

### Solution
Replace the for-loop in `BaseScanner.scan()` with `ThreadPoolExecutor`:

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_PARALLEL_CHECKS = 10

def scan(self, token, pool):
    ctx = self._build_context(token, pool)
    findings = []
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_CHECKS) as pool:
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
                    description=f"Check failed: {exc}",
                    recommendation="Manual review",
                ))
    # ... confidence scoring ...
    return ScanReport(...)
```

### Key Design Decisions
- `max_workers=10`: balances concurrency vs RPC rate limits (most public RPCs allow ~10-20 concurrent requests)
- Checks are stateless (each is a fresh `cls()`) — thread-safe by construction
- `DataCollector` cache is shared across threads (read-only dict after initial fill + concurrent writes are safe for CPython dict)
- Error handling preserved (per-check exceptions caught as before)

### Impact
- 28 checks now run in ~3 batches of 10 instead of 28 sequential
- ~5-8x speedup per token
- Files: `src/scanners/base.py` only (~20 lines changed)

---

## Phase 3: Worker Pool for Multiple Tokens

### Problem
- `Analyzer.run()` processes one token at a time
- Retro-scan of 500+ tokens would take hours

### Solution
Replace single-token loop with configurable worker pool:

```python
class Analyzer:
    def __init__(self, ..., max_workers: int = 4):
        self._max_workers = max_workers
    
    def run_parallel(self):
        """Process up to max_workers tokens concurrently."""
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = {}
            while self._running:
                # Queue management (non-blocking)
                items = self._queue.claim_next_batch(self._max_workers)
                for item in items:
                    fut = executor.submit(self._process_one, item)
                    futures[fut] = item
                
                # Collect completed
                done, _ = concurrent.futures.wait(
                    futures, timeout=1.0,
                    return_when=FIRST_COMPLETED
                )
                for fut in done:
                    item = futures.pop(fut)
                    try:
                        fut.result()
                        self._queue.mark_done(item)
                    except Exception as e:
                        self._queue.mark_failed(item, str(e))
```

Alternative: keep existing `process_one()` + `claim_next()` loop but add a `Semaphore`/`ThreadPoolExecutor` that processes in background. Simpler:

```python
def run(self):
    pool = ThreadPoolExecutor(max_workers=self._max_workers)
    pending = []
    while self._running:
        if len(pending) < self._max_workers:
            token = self._queue.claim_next()
            if token:
                fut = pool.submit(self._scan_and_report, token)
                pending.append(fut)
        # collect done
        done = [f for f in pending if f.done()]
        for f in done:
            f.result()  # propagate errors
            pending.remove(f)
        if not pending and not token:
            sleep(1.0)
```

### Design Choice
- `max_workers=4`: default — safe for public RPC limits. User-configurable via env/config.
- Each worker thread uses its own `DataCollector` with shared cache.
- Queue `claim_next()` becomes thread-safe (SQLite with WAL mode supports concurrent reads).
- Error isolation: one token failure doesn't affect others.

### Impact
- ~Nx speedup where N = min(max_workers, RPC rate limit headroom)
- For retro-scan of 500 tokens: from ~hours to ~minutes
- Files: `src/analyzer.py`, `src/db/queue.py` (thread-safe claim_next)

---

## Why Not Full Async

| Factor | Sync + ThreadPool | Full asyncio |
|--------|------------------|--------------|
| Files changed | 3 (`data.py`, `base.py`, `analyzer.py`) | 25+ (every check + RPC + scanner) |
| Risk | Low (additive changes) | High (every check needs async rewrite) |
| Peak perf | ~30x | ~40x |
| Debugging | Normal | Complex (async stack traces) |
| Check thread-safety | Already stateless | Must audit all checks |

ThreadPoolExecutor gives 80% of the benefit for 10% of the effort.

---

## Testing Strategy

| Phase | Tests | Approach |
|-------|-------|----------|
| 1. Cache | `test_data.py` +cache tests | Verify same call returns cached result, different params don't collide |
| 2. Parallel checks | `test_evm_scanner.py` +tests | Verify all findings collected, exceptions handled, no race conditions |
| 3. Worker pool | `test_analyzer.py` +tests | Verify N tokens processed, queue state correct |

Existing tests must continue to pass after each phase.

---

## Configuration

```python
# config or env vars
MAX_PARALLEL_CHECKS = 10    # per token
MAX_WORKERS = 4              # parallel tokens
RPC_TIMEOUT = 30             # seconds
```

---

## Success Criteria

- Phase 1: Same scan produces 60% fewer RPC calls, results identical
- Phase 2: Single token scan completes in 3-8s (down from 15-45s)
- Phase 3: Retro-scan of 500 tokens completes in 5-15 minutes
- All 342+ existing tests pass unchanged
