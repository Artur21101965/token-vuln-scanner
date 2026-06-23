# Multi-Profile Vulnerability Scanner — Design Spec

## Overview
A multi-profile token vulnerability scanner that finds real money-draining exploits across 10 EVM chains + Solana. Each profile defines *how* to discover targets, *what* to check for, and *what* to do with findings.

## Architecture

```
Profiles (config) → Orchestrator → Discovery → Checks → Verifier → Action
                                   (retro)    (drain)  (eth_call)  (alert)
                                   (bytecode) (mint)   (simulate)  (verify)
                                   (deployer) (control)            (exploit)
```

## Profile Definition (config.toml)

```toml
[profile.evm-drain-deep]
chains = ["ethereum", "bsc", "base", "arbitrum", "polygon", "avalanche", "optimism"]
discovery = ["retro", "bytecode"]
checks = ["drain"]
action = "verify"

[profile.solana-all-scan]
chains = ["solana"]
discovery = ["retro"]
checks = ["all"]
action = "alert"

[profile.evm-exploit]
chains = ["bsc", "base", "arbitrum"]
discovery = ["retro", "bytecode", "deployer"]
checks = ["drain", "control"]
action = "exploit"
```

Default profile is `evm-drain-deep` when none specified.

## Discovery Methods

### 1. retro — Retrospective Bulk Scan
- Query DEX Screener with 8 liquidity-bearing terms per chain
- Collect 500-2000+ token addresses per chain
- Prioritize by liquidity USD
- Store in queue for analysis
- Runs once at startup, then periodic refresh

### 2. bytecode — Bytecode Pattern Scan
For each discovered token:
- Fetch bytecode via `eth_getCode`
- Check for specific patterns using the existing EVM checks (they already search for selectors in bytecode)
- Add a new check: "contract uses custom bytecode" (not a standard ERC20 factory pattern)
- Flag custom contracts for deeper verification

### 3. deployer — Deployer Clustering
- When a vulnerable contract is found, extract deployer address (via tx receipt or storage)
- Look up all other tokens deployed by the same address
- Add them to the queue for priority scanning
- Build deployer reputation over time

## Check Profiles

| Profile | Checks Included | Category |
|---------|----------------|----------|
| drain | unprotected_withdraw, selfdestruct, reentrancy, delegatecall | ETH/token drain |
| mint | unprotected_mint, mint_function_unprotected, supply_manipulation | Token creation |
| control | public_ownership_transfer, unprotected_initialize, unprotected_upgrade, proxy_checks | Ownership takeover |
| all | All of the above + honeypot, blacklist, tax, limits | Full audit |

## Action Modes

| Mode | Behavior |
|------|----------|
| alert | Log finding, send Telegram if confidence ≥ 0.9 |
| verify | Run existing SimulatedExploitVerifier + SolanaExploitVerifier |
| exploit | After verify passes, sign + send real tx via executor |

## Implementation Plan

### Phase 1: Discovery Engine
- Extend `TopTokenScanner` with:
  - `scan_retro_bulk()` — 2000 tokens/chain via DEX Screener
  - `scan_by_bytecode()` — bytecode fetch + pattern match
  - `scan_by_deployer()` — deployer cluster tracking

### Phase 2: Profile Orchestrator
- Parse profile from config
- Select discovery/checks/action based on profile
- Run appropriate scanner loops

### Phase 3: Check Grouping
- Tag each EVM check with profile category
- Add `drain` category tag
- Filter by active profile

### Phase 4: Exploit Routing
- Wire `ExploitExecutor` into action pipeline
- Action=exploit: after verify confirms, send real tx

## Current System (unchanged)
- 239 passing tests
- Existing EVM checks (226) + Solana checks (3)
- SimulatedExploitVerifier, HoneypotVerifier, SolanaExploitVerifier
- MempoolMonitor
- Wallet/signer system
- Telegram notifications

## Targets
- EVM: 10 chains (Ethereum, BSC, Arbitrum, Base, Polygon, Avalanche, Optimism, zkSync, Linea, Scroll)
- Solana (authority + pool ownership checks)
- Any chain with DEX Screener data
