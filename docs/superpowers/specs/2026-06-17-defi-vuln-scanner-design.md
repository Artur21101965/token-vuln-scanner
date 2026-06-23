# DeFi Vulnerability Scanner — Design Doc

## Goal

Расширить текущий `token-vuln-scanner` с токен-аудита на поиск уязвимостей в любых
смарт-контрактах на 10+ EVM-сетях через публичные RPC. Для каждой найденной
уязвимости генерировать exploit plan — пошаговую инструкцию с возможностью
автовыполнения.

## Sources

Новые источники адресов для сканирования (поверх текущих DexScreener топ-токенов):

| Source | Что даёт | Получение |
|--------|----------|-----------|
| Recent Blockscout contracts | Свежие заверифицированные контракты на 10 сетях | Blockscout API /latest-verified |
| Known addresses | Пулы, роутеры, фабрики, прокси из уже просканированных токенов | Выбираются из `TokenPool` и `CheckContext` |
| Stale by balance | Контракты с ETH балансом, не вызывавшиеся 180+ дней | Сканирование через RPC в фоне |

## Vulnerability Layers

### Layer 1 — Tokens (exists, 28 checks)
honeypot, taxes, owner, proxy, mintable, paused, blacklist, fake LP, etc.

### Layer 2 — Uninitialized Proxy (new)
**Detection:**
1. Read ERC1967 implementation slot: `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`
2. If implementation != 0, get implementation bytecode
3. Scan bytecode for `initialize()` selector: `0x8129fc1c` (and common init selectors)
4. Call `initialize()` via eth_call from a random address
5. If it succeeds (doesn't revert) — proxy is **uninitialized**
6. Also check ETH + ERC20 balance of the proxy

**Exploit plan:**
```
Type: uninitialized_proxy
Target: 0x...
Implementation: 0x...
Chain: Ethereum
Eth balance: X ETH
ERC20 tokens: Y USDC, Z WETH

Steps:
1. Call initialize(new_admin=YOUR_ADDR) on proxy
2. Call implementation.withdrawAll(YOUR_ADDR) on proxy
3. Transfer drained tokens to cold wallet
```

### Layer 2 — Unprotected Drain Functions (new)
**Detection:**
1. Get ABI via Blockscout (if verified) or parse bytecode dispatch table
2. Find function selectors for: `withdraw`, `sweep`, `emergencyWithdraw`, `drain`, `claim`, `collect`, `recover`
3. Check access control: scan ABI for `onlyOwner`/`auth` modifiers, scan bytecode for `require(msg.sender)` patterns
4. Simulate the call via eth_call: if balance decreases → unprotected
5. Filter: only flag contracts with non-zero ETH/ERC20 balance

**Exploit plan:**
Same format as proxy: target → function call → expected outcome → gas estimate.

### Layer 3 — Stale/Forgotten (future)
- Contracts with ETH balance, no tx in 180+ days
- Owner is EOA with zero ETH balance (key lost)
- Renounced ownership via burn address

### Layer 4 — Permission Bugs (future)
- Public `delegatecall` to arbitrary address
- Public `selfdestruct`
- Unlimited approvals to suspicious addresses

### Layer 5 — LP & Staking (future)
- Unburned LP tokens (liquidity can be drained by anyone)
- Staking with broken `emergencyUnstake`

### Layer 6 — Bridge & Cross-chain (future)
- Stuck funds in halted bridges
- Low-security relayers

### Layer 7 — MEV & Manipulation (future)
- Spot-price oracles without TWAP
- Sandwich-vulnerable pools

## Architecture

### Check classes

New checks follow same pattern as existing token checks:

```
src/checks/
  ├── __init__.py
  ├── defi/
  │   ├── __init__.py
  │   ├── uninitialized_proxy.py      # CheckUninitializedProxy
  │   └── unprotected_drain.py        # CheckUnprotectedDrain
  ...
```

Each check returns `Finding` with:
- `check_name`: `uninitialized_proxy` / `unprotected_drain`
- `severity`: CRITICAL for both
- `details`: contract address, implementation, balance, function selectors
- `confidence`: from main scanner pipeline

### Verifier classes

```
src/verifiers/
  ├── ...
  ├── exploit_proxy.py                # ProxyExploitVerifier
  └── exploit_drain.py                # DrainExploitVerifier
```

Each verifier:
1. Takes the Finding
2. Calls real RPC functions to simulate exploit
3. Returns `VerificationResult` with `confirmed`, `confidence`, `evidence`
4. Fills `exploit_plan` in `Finding.details` — structured steps for exploit

### ExploitPlan format

```json
{
  "type": "uninitialized_proxy",
  "target": "0x...",
  "chain": "ethereum",
  "eth_balance": "12.5",
  "token_balances": {"USDC": "15000.0"},
  "steps": [
    {
      "action": "call",
      "target": "0x...",
      "function": "initialize",
      "params": ["0xYOUR_ADDR"],
      "description": "Set yourself as admin"
    },
    {
      "action": "call",
      "target": "0x...",
      "function": "withdrawAll",
      "params": ["0xYOUR_ADDR"],
      "description": "Drain all ETH + ERC20"
    }
  ],
  "gas_estimate": 120000,
  "profit_estimate_usd": 37000,
  "auto_command": "python src/exploit/run.py --target 0x..."
}
```

### AddressSource abstraction

To support multiple address sources, refactor current `TokenQueue` into `AddressSource`:

```python
class AddressSource(ABC):
    @abstractmethod
    def get_batch(self, batch_size: int) -> list[ScanTarget]: ...

class DexScreenerTokens(AddressSource):  # current
class BlockscoutRecent(AddressSource):   # new
class StaleContractScan(AddressSource):  # future
```

Each `ScanTarget` has:
- `address: str`
- `chain: Chain`
- `source: str` (for tracking where it came from)
- `context: dict` (pool info, token info, etc.)

## Implementation Order

1. **Checks:** CheckUninitializedProxy + CheckUnprotectedDrain
2. **Verifiers:** ProxyExploitVerifier + DrainExploitVerifier
3. **ExploitPlan:** format + serialization in Finding.details
4. **Source:** BlockscoutRecent contracts fetcher
5. **Integration:** scanner pipeline handles all sources, all checks
6. **Output:** exploit plan rendered in CLI + JSON log

## Testing

- **Unit:** each check with mocked bytecode/ABI
- **Integration:** eth_call simulation on test contracts
- **Regression:** all current 354 tests must still pass

## Non-goals

- No private keys stored in scanner
- No actual transactions sent by scanner (only simulation)
- No MEV/flash loan simulation (Layer 7, future)
- No off-chain vulnerability scanning (frontend, API keys, infra)
