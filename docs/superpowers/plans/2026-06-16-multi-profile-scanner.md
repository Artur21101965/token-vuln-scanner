# Multi-Profile Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the multi-profile vulnerability scanner with retro bulk discovery, profile-based scanning, and exploit execution

**Architecture:** Profile config → Orchestrator selects discovery method → feeds tokens to check pipeline → routes results to action (alert/verify/exploit)

**Tech Stack:** Python 3.12, eth_account, solders, DEX Screener API, httpx

---

### Task 1: Retro Bulk Scanner — find 2000+ tokens per chain

**Files:**
- Modify: `src/monitors/top_token_scanner.py`
- Test: `tests/test_top_token_scanner.py`

- [ ] Step 1: Write the failing test

Add to `test_top_token_scanner.py`:

```python
def test_scan_retro_bulk_produces_tokens():
    queue = TokenQueue(db_path=":memory:")
    queue.init_db()
    scanner = TopTokenScanner(queue=queue, min_liquidity=100)
    # Should add tokens to queue without error
    try:
        scanner.scan_retro_bulk(chains=[Chain.BSC], max_per_chain=5)
    except Exception as e:
        pytest.fail(f"scan_retro_bulk raised: {e}")
    assert queue.pending_count() > 0
```

- [ ] Step 2: Run test — expect FAIL (method doesn't exist)

Run: `uv run pytest tests/test_top_token_scanner.py::test_scan_retro_bulk_produces_tokens -x --tb=short`

- [ ] Step 3: Implement `scan_retro_bulk` in `TopTokenScanner`

Add to `src/monitors/top_token_scanner.py`:

```python
import requests
import logging
from typing import Optional
from src.types import PendingToken, Chain, TokenStatus
from decimal import Decimal

logger = logging.getLogger(__name__)

LIQUIDITY_TERMS = [
    "token", "dexscreener", "0x", "dapp", "swap",
    "DEFI", "STAKE", "FARM", "YIELD", "AIRDROP",
    "BRIDGE", "NFT", "MEME", "TEST",
]

# Chain name mapping for DEX Screener
DEX_CHAIN_NAMES = {
    Chain.ETHEREUM: "ethereum",
    Chain.BSC: "bsc",
    Chain.ARBITRUM: "arbitrum",
    Chain.BASE: "base",
    Chain.POLYGON: "polygon",
    Chain.AVALANCHE: "avalanche",
    Chain.OPTIMISM: "optimism",
    Chain.ZKSYNC: "zksync",
    Chain.LINEA: "linea",
    Chain.SCROLL: "scroll",
    Chain.SOLANA: "solana",
}

def scan_retro_bulk(self, chains: Optional[list[Chain]] = None, max_per_chain: int = 500):
    chains = chains or list(DEX_CHAIN_NAMES.keys())
    total = 0
    seen = set()
    for chain in chains:
        dex_chain = DEX_CHAIN_NAMES.get(chain, "")
        if not dex_chain:
            continue
        chain_count = 0
        for term in LIQUIDITY_TERMS:
            if chain_count >= max_per_chain:
                break
            try:
                resp = requests.get(
                    f"https://api.dexscreener.com/latest/dex/search/?q={term}",
                    timeout=10,
                ).json()
            except Exception:
                continue
            pairs = resp.get("pairs", []) if isinstance(resp, dict) else []
            for pair in pairs:
                if chain_count >= max_per_chain:
                    break
                chain_id = (pair.get("chainId") or "").lower()
                if chain_id != dex_chain:
                    continue
                base = pair.get("baseToken", {})
                addr = (base.get("address") or "").lower()
                if not addr or addr in seen:
                    continue
                seen.add(addr)
                liq = Decimal(str(pair.get("liquidity", {}).get("usd", 0) or 0))
                if liq < self._min_liquidity:
                    continue
                symbol = (base.get("symbol") or "?")[:20]
                token = PendingToken(
                    chain=chain,
                    token_address=addr,
                    symbol=symbol,
                    liquidity_usd=liq,
                    dex=pair.get("dexId", ""),
                    pair_address=pair.get("pairAddress", ""),
                    status=TokenStatus.PENDING,
                )
                self._queue.enqueue(token)
                chain_count += 1
                total += 1
    logger.info("Retro bulk scan: %d tokens queued across %d chains", total, len(chains))
```

- [ ] Step 4: Run test — expect PASS

Run: `uv run pytest tests/test_top_token_scanner.py::test_scan_retro_bulk_produces_tokens -x --tb=short`

- [ ] Step 5: Run full test suite

Run: `uv run pytest tests/ -x --tb=short -q`

### Task 2: Profile Config + Orchestrator

**Files:**
- Modify: `config.toml`
- Create: `src/orchestrator.py`
- Modify: `run_analyzer.py`
- Test: `tests/test_orchestrator.py`

- [ ] Step 1: Write the test

```python
import pytest
from src.orchestrator import Profile, load_profile
from src.types import Chain

def test_load_profile_default():
    profile = load_profile()
    assert profile.name == "evm-drain-deep"
    assert "ethereum" in profile.chains
    assert "drain" in profile.checks

def test_load_profile_custom():
    profile = load_profile("solana-all-scan")
    assert profile.chains == [Chain.SOLANA]
    assert "all" in profile.checks
    assert profile.action == "alert"

def test_profile_check_filter():
    profile = Profile(name="test", chains=[Chain.ETHEREUM], checks=["drain"], discovery=["retro"], action="alert")
    assert profile.should_run_check("unprotected_withdraw") is True
    assert profile.should_run_check("unprotected_mint") is False
    assert profile.should_run_check("unprotected_ownership_transfer") is False
```

- [ ] Step 2: Run test — expect FAIL

Run: `uv run pytest tests/test_orchestrator.py -x --tb=short`

- [ ] Step 3: Add profile defaults to config.toml

Append to `config.toml`:

```toml
[profile.evm-drain-deep]
chains = ["ethereum", "bsc", "base", "arbitrum", "polygon", "avalanche", "optimism", "zksync", "linea", "scroll"]
discovery = ["retro"]
checks = ["drain"]
action = "verify"

[profile.evm-all-scan]
chains = ["ethereum", "bsc", "base", "arbitrum", "polygon", "avalanche", "optimism", "zksync", "linea", "scroll"]
discovery = ["retro"]
checks = ["all"]
action = "alert"

[profile.solana-all-scan]
chains = ["solana"]
discovery = ["retro"]
checks = ["all"]
action = "alert"

[profile.solana-exploit]
chains = ["solana"]
discovery = ["retro"]
checks = ["all"]
action = "verify"
```

- [ ] Step 4: Create `src/orchestrator.py`

```python
"""Profile orchestrator — selects discovery/checks/action based on profile config."""
import logging
import tomllib
from typing import Optional, get_type_hints
from src.types import Chain

logger = logging.getLogger(__name__)
CONFIG_PATH = "config.toml"

CHECK_CATEGORIES: dict[str, set[str]] = {
    "drain": {
        "unprotected_withdraw",
        "selfdestruct_in_code",
        "reentrancy_call",
        "delegatecall_to_user",
    },
    "mint": {
        "unprotected_mint",
        "mint_function_unprotected",
    },
    "control": {
        "public_ownership_transfer",
        "unprotected_initialize",
        "unprotected_upgrade",
        "proxy_unchecked_upgrade",
    },
    "all": set(),  # All checks
}

DEFAULT_PROFILE = "evm-drain-deep"


class Profile:
    def __init__(self, name: str, chains: list[Chain], discovery: list[str],
                 checks: list[str], action: str):
        self.name = name
        self.chains = chains
        self.discovery = discovery
        self.action = action
        self._check_names = set()
        for c in checks:
            if c == "all":
                for cat in CHECK_CATEGORIES.values():
                    self._check_names.update(cat)
                break
            cats = CHECK_CATEGORIES.get(c, {c})
            self._check_names.update(cats)

    def should_run_check(self, check_name: str) -> bool:
        if not self._check_names:
            return True
        return check_name in self._check_names


def _load_config(path: str = CONFIG_PATH) -> dict:
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


def load_profile(name: Optional[str] = None) -> Profile:
    cfg = _load_config()
    profiles = cfg.get("profile", {})
    name = name or DEFAULT_PROFILE
    pcfg = profiles.get(name, profiles.get(DEFAULT_PROFILE, {}))

    chain_map = {
        "ethereum": Chain.ETHEREUM, "bsc": Chain.BSC, "arbitrum": Chain.ARBITRUM,
        "base": Chain.BASE, "polygon": Chain.POLYGON, "avalanche": Chain.AVALANCHE,
        "optimism": Chain.OPTIMISM, "zksync": Chain.ZKSYNC, "linea": Chain.LINEA,
        "scroll": Chain.SCROLL, "solana": Chain.SOLANA,
    }
    chains = [chain_map[c] for c in pcfg.get("chains", ["ethereum"]) if c in chain_map]
    return Profile(
        name=name,
        chains=chains,
        discovery=pcfg.get("discovery", ["retro"]),
        checks=pcfg.get("checks", ["drain"]),
        action=pcfg.get("action", "alert"),
    )
```

- [ ] Step 5: Run tests — expect PASS

Run: `uv run pytest tests/test_orchestrator.py -x --tb=short`

- [ ] Step 6: Update `run_analyzer.py` to use profile

At top of `main()`, add:

```python
import sys
# ...
def main():
    profile_name = sys.argv[1] if len(sys.argv) > 1 else None
    profile = load_profile(profile_name)
    logger.info("Active profile: %s (chains=%s, checks=%s, action=%s)",
                profile.name, [c.name for c in profile.chains],
                profile.checks if hasattr(profile, '_check_names') else 'all', profile.action)
```

Then modify scanner creation to only create scanners for chains in the profile:

```python
scanners: dict[Chain, EvmScanner | SolanaScanner] = {}
slot_monitors: dict[Chain, SlotMonitor] = {}

if profile._check_names & {'unprotected_withdraw', 'selfdestruct_in_code', 'reentrancy_call',
                            'unprotected_mint', 'mint_function_unprotected',
                            'public_ownership_transfer', 'unprotected_initialize',
                            'unprotected_upgrade'}:
    evm_chains = [ ... ]  # only chains in profile
    # ... existing EVM setup filtered by profile.chains
```

- [ ] Step 7: Run full test suite

Run: `uv run pytest tests/ -x --tb=short -q`

### Task 3: Retro Scan on Startup

**Files:**
- Modify: `run_analyzer.py`
- Modify: `src/analyzer.py`

- [ ] Step 1: Run retro bulk scan on startup

In `run_analyzer.py` `main()`, after scanner setup:

```python
if "retro" in profile.discovery:
    logger.info("Running retro bulk scan...")
    try:
        retro_chains = [c for c in profile.chains if c != Chain.SOLANA]
        top_scanner.scan_retro_bulk(chains=retro_chains, max_per_chain=500)
    except Exception as e:
        logger.error("Retro scan failed: %s", e)
```

- [ ] Step 2: Verify retro scan runs

Run: `uv run python run_analyzer.py evm-drain-deep 2>&1 | head -20`

### Task 4: Check Grouping — filter checks by profile

**Files:**
- Create: `src/scanners/checks/registry.py`
- Modify: `src/scanners/evm_scanner.py`
- Modify: `src/scanners/solana_scanner.py`
- Test: `tests/test_check_registry.py`

- [ ] Step 1: Write test

```python
import pytest
from src.scanners.checks.registry import get_checks_for_profile, CHECK_CATEGORIES

def test_drain_checks():
    checks = get_checks_for_profile(["drain"])
    assert "unprotected_withdraw" in checks
    assert "unprotected_mint" not in checks

def test_all_checks():
    checks = get_checks_for_profile(["all"])
    assert len(checks) > 10

def test_unknown_category():
    checks = get_checks_for_profile(["nonexistent"])
    assert len(checks) == 0
```

- [ ] Step 2: Run test — expect FAIL

Run: `uv run pytest tests/test_check_registry.py -x --tb=short`

- [ ] Step 3: Create `src/scanners/checks/registry.py`

```python
"""Check registry — maps profile categories to check names."""

CHECK_CATEGORIES: dict[str, set[str]] = {
    "drain": {
        "unprotected_withdraw",
        "selfdestruct_in_code",
        "reentrancy_call",
    },
    "mint": {
        "unprotected_mint",
        "mint_function_unprotected",
    },
    "control": {
        "public_ownership_transfer",
        "unprotected_initialize",
        "unprotected_upgrade",
    },
}


def get_checks_for_profile(categories: list[str]) -> set[str]:
    result: set[str] = set()
    for cat in categories:
        if cat == "all":
            for v in CHECK_CATEGORIES.values():
                result.update(v)
            return result
        names = CHECK_CATEGORIES.get(cat)
        if names:
            result.update(names)
    return result
```

- [ ] Step 4: Run test — expect PASS

Run: `uv run pytest tests/test_check_registry.py -x --tb=short`

### Task 5: Wire Exploit Action into Scanner

**Files:**
- Modify: `src/exploit_executor.py`
- Modify: `src/scanners/evm_scanner.py`

- [ ] Step 1: Add test for exploit routing

```python
def test_executor_routes_correctly():
    from src.exploit_executor import ExploitExecutor
    from unittest.mock import MagicMock
    executor = ExploitExecutor(signer=MagicMock())
    finding = Finding(check_name="unprotected_withdraw", severity=Severity.CRITICAL,
                      description="test", recommendation="test",
                      details={"selector": "2e1a7d4d"})
    assert executor.can_execute(finding) is True
```

- [ ] Step 2: In `EvmScanner.scan()`, after verification, if action is "exploit" and verified confidence >= 0.9, call executor

Add to `src/scanners/evm_scanner.py`:

```python
def scan(self, token: TokenInfo, pool: PoolInfo, exploit_action: bool = False) -> ScanReport:
    report = super().scan(token, pool)
    # ...existing verification logic...
    if exploit_action and self._executor:
        for f in report.findings:
            if f.details.get("verification_confidence", 0) >= 0.9:
                ctx = CheckContext(token=token, pool=pool, data_collector=self._data, rpc=self._rpc)
                self._executor.execute(ctx, f)
    return report
```

- [ ] Step 3: Add executor to EvmScanner constructor

```python
def __init__(self, data_collector, rpc, verifier_runner=None, deployer_store=None, executor=None):
    super().__init__(data_collector, rpc, deployer_store=deployer_store)
    self._verifier_runner = verifier_runner
    self._executor = executor
```

- [ ] Step 4: Pass executor in `run_analyzer.py` when action == "exploit"

```python
if profile.action == "exploit":
    from src.exploit_executor import ExploitExecutor
    executor = ExploitExecutor()
else:
    executor = None
```

Then pass `executor=executor` to `_build_evm_scanner()`.

- [ ] Step 5: Run full suite

Run: `uv run pytest tests/ -x --tb=short -q`

### Task 6: Update run scripts — profile as argument

**Files:**
- Modify: `run_analyzer.py`

- [ ] Step 1: Accept profile name from command line

At `main()`:

```python
def main():
    import sys
    profile_name = sys.argv[1] if len(sys.argv) > 1 else None
```

Usage: `uv run python run_analyzer.py solana-all-scan`

- [ ] Step 2: Run and verify

```bash
uv run python run_analyzer.py evm-drain-deep 2>&1 | head -5
```
Expected: Shows active profile log line.

### Task 7: Run full test suite — 239+ tests pass

Run: `uv run pytest tests/ -x --tb=short -q`
Expected: All tests pass.
