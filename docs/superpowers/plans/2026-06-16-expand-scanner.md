# Scanner Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add deployer analysis, periodic top-token REST scanning, DEX pool event monitoring, and multi-send detection.

**Architecture:** 4 independent subsystems. Each adds files under `src/` and registers into existing analyzer/monitor flow.

**Tech Stack:** Python, SQLite, httpx, eth_getLogs (RPC), DexScreener REST API

---

## File Structure

```
src/
  db/
    deployer_store.py      (NEW) — deployer SQLite table + queries
  monitors/
    pool_monitor.py        (NEW) — watches Uniswap V2 factory PairCreated events
    top_token_scanner.py   (NEW) — periodic DexScreener REST top-token discovery
  scanners/
    checks/
      evm/
        multi_send.py      (NEW) — detects multi-send token distributions
        scam_deployer.py   (NEW) — flags known-scammer deployers
  analyzer.py              (MODIFY) — wire deployer tracking + top token scan
  data.py                  (MODIFY) — add get_creator_address method
  rpc.py                   (MODIFY) — add eth_get_logs + eth_get_transaction_receipt
  types.py                 (MODIFY) — add DeployerInfo dataclass
  monitor.py               (MODIFY) — periodic top-token discovery
run_analyzer.py            (MODIFY) — wire deployer store
run_monitor.py             (MODIFY) — wire pool monitor
config.toml                (MODIFY) — add pool factory addresses
```

### Task 1: Deployer Analysis

**Files:**
- Create: `src/db/deployer_store.py`
- Create: `src/scanners/checks/evm/scam_deployer.py`
- Create: `tests/test_checks/test_scam_deployer.py`
- Create: `tests/test_deployer_store.py`
- Modify: `src/types.py` — add `DeployerInfo` dataclass
- Modify: `src/data.py` — add `get_creator_address()`
- Modify: `src/rpc.py` — add `eth_get_transaction_receipt()`
- Modify: `src/explorer.py` — add `get_creator_address()`
- Modify: `src/analyzer.py` — track deployer after scan
- Modify: `run_analyzer.py` — wire DeployerStore
- Modify: `tests/test_analyzer.py` — update for deployer tracking

**Overview:** Track contract creator addresses per token. When a deployer has 3+ tokens with CRITICAL findings, new tokens from same deployer get flagged.

### Task 2: Periodic Top-Token REST Scan

**Files:**
- Create: `src/monitors/top_token_scanner.py`
- Create: `tests/test_top_token_scanner.py`
- Modify: `src/monitor.py` — periodic top-token fetch (or add to analyzer idle)

**Overview:** Every 30 min during idle, fetch DexScreener token-boosts API for trending tokens on all chains, enqueue any not yet scanned.

### Task 3: DEX Pool Event Monitor

**Files:**
- Create: `src/monitors/pool_monitor.py`
- Create: `src/monitors/factory_addresses.py`
- Create: `tests/test_pool_monitor.py`
- Create: `run_pool_monitor.py`
- Modify: `config.toml`
- Modify: `src/rpc.py` — add `get_logs()`

**Overview:** Watch Uniswap V2 factory contracts on each EVM chain for PairCreated events. On detection, queue the token for scanning.

### Task 4: Multi-Send Detection

**Files:**
- Create: `src/scanners/checks/evm/multi_send.py`
- Create: `tests/test_checks/test_multi_send.py`
- Modify: `src/scanners/checks/evm/__init__.py` — register check

**Overview:** When scanning a token, check recent Transfer logs. If a single tx distributed tokens to 50+ recipients in one block, flag as multi-send (CRITICAL — potential pump distribution).

---
