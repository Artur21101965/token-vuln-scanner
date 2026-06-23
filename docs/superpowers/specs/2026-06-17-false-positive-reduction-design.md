# Anti-False-Positive System

## Problem

Current scanner produces false positives in two scenarios:

1. **Fallback/forwarding contracts**: Any contract with a catch-all fallback (returns `0x` for unrecognized selectors) makes ALL `eth_call`-based verifications succeed. The scanner flags these as CONFIRMED when they're not callable. Tested: `0x51C72848c68a965f66FA7a88855F9f7784502a7F` — a forwarding router with 20KB bytecode, 62 dispatcher entries, and a fallback that returns `0x` for every selector.

2. **Selector-in-bytecode false matches**: The scanner searches for PUSH4 patterns anywhere in bytecode. Function selectors that appear inside function bodies (as data, JUMPTABLE entries, or embedded constants) are reported as callable functions even when they're not in the dispatcher.

## Solution: 3 Components

### 1. Fallback Detector

Before running `eth_call` verification, check if the contract has a fallback:

- Call an impossible selector (e.g., `0xdeadbeef` with 32 zero bytes)
- If RPC returns `0x` (success) without revert → contract has catch-all fallback
- Flag ALL `eth_call` verifications for this contract as `UNRELIABLE`

### 2. Dispatch Table Analyzer

Module `src/evm/dispatch_table.py`:

Parse the actual function dispatch table from EVM bytecode:
- Pattern: `CALLDATALOAD` → `SHR` → `PUSH4` → `EQ` → `JUMPI`
- Alternative: `CALLDATALOAD` → `PUSH1 0xe0` → `SHR` → `DUP1` → `PUSH4` → `EQ` → `PUSH2 dest` → `JUMPI`
- Return: set of `(selector_hex, jump_destination)` for each function
- Return: `fallback_offset` if a fallback handler exists (no selector match → REVERT or JUMP)

Only report functions that are **actually in the dispatch table**. Functions found elsewhere in bytecode (as data/constants/internal references) are filtered out.

### 3. Confidence Scoring System

Module `src/verifiers/confidence.py`:

Replace binary CONFIRMED/DISMISSED with confidence score 0.0–1.0:

| Condition | Confidence | Action |
|-----------|-----------|--------|
| Fallback detected | 0.0 | All eth_call verifications for this contract are unreliable |
| Fallback detected + func in dispatch table | 0.3 | Finding visible, but marked LOW confidence |
| No fallback, func in dispatch table | 0.7 | Standard confidence |
| eth_call reverted (access control works) | 0.0 | DISMISSED |
| eth_call succeeded + dispatch table + suspicious | 0.9 | HIGH confidence |
| eth_call succeeded + value extracted in test | 1.0 | CONFIRMED (requires manual test tx) |

### Integration

- **Bytecode checks** (`bytecode_selfdestruct`, `bytecode_delegatecall`, `bytecode_sstore`): use dispatch table instead of raw PUSH4 scan
- **Selector checks** (unprotected_mint, withdraw, upgrade, etc.): before reporting, confirm selector is in dispatch table
- **Scanner pipeline**: after all checks run, confidence filter removes findings with score < 0.5
- **Noise reduction pass**: findings from contracts with fallback get demoted by one severity level

### Testing

- Unit test for dispatch table parser: Uniswap V2 router (known dispatcher), 0x Exchange Proxy, forwarding contract address
- Unit test for fallback detector: mock RPC returning success/failure for deadbeef
- Unit test for confidence scorer: all combinations of conditions
- Integration test: verify 0x51c7... no longer produces false CRITICAL for withdraw

## Files

- `src/evm/dispatch_table.py` — dispatch table parser
- `src/verifiers/confidence.py` — confidence scoring
- `src/scanners/base.py` — integrate confidence scoring into scan pipeline
- `src/data.py` — add fallback detection to DataCollector

## Not In Scope

- Real swap simulation for honeypot detection (separate phase)
- Parallel scanning infrastructure
- Database migration
