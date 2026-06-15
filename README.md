# Token Vulnerability Scanner

Monitors newly deployed tokens on Ethereum (Uniswap), BSC (PancakeSwap), and Solana (Raydium) with liquidity > $500, scans them for contract vulnerabilities, and writes local reports.

## Architecture

Two independent processes connected via a SQLite queue:

- **Monitor** — listens to DexScreener WebSocket, filters pairs with >$500 liquidity, writes to queue
- **Analyzer** — picks tokens from the queue, runs 20+ vulnerability checks, writes JSON reports

## Quick Start

```bash
pip install -r requirements.txt

# Terminal 1 — start monitor
python run_monitor.py

# Terminal 2 — start analyzer
python run_analyzer.py
```

## Configuration

Edit `config.toml` to set your RPC URLs and API keys:

```toml
[rpc]
ethereum = "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
bsc = "https://bsc-mainnet.g.alchemy.com/v2/YOUR_KEY"
solana = "https://api.mainnet-beta.solana.com"
```

## Reports

Reports are written to `reports/<chain>/<token_address>/report.json` with a companion `findings.txt`.

Example report structure:
```
reports/
  ethereum/
    0xabc123.../
      report.json
      findings.txt
```

## Supported Vulnerability Checks

### EVM (Ethereum, BSC)
- Ownership renounced
- Mint function unprotected
- LP tokens not burned
- Honeypot (manual review)
- Upgradeable proxy (delegatecall)
- Pausable token
- High tax/fees
- Blacklist/whitelist
- Max transaction/wallet limits
- Selfdestruct in code
- Reentrancy risk
- AccessControl roles active

### Solana
- Mint authority not revoked
- Freeze authority active
- Pool ownership not renounced
- LP not locked
- Token-2022 extensions

## Requirements

- Python 3.11+
- RPC endpoint for each chain (Infura/Alchemy for Ethereum, public RPC for others)
- Etherscan/BscScan API keys (optional — for ABI resolution)

## Running 24/7

```bash
# Using systemd or tmux/screen:
tmux new -s monitor  'python run_monitor.py'
tmux new -s analyzer 'python run_analyzer.py'
```
