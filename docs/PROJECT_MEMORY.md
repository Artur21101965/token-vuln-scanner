# Monster Exploit Scanner — Полная карта проекта

> Последнее обновление: 2026-06-23. 28 процессов. 45 проверок. Flash Loan контракт на Polygon.

---

## НОВЫЙ ЧАТ — СТАРТОВЫЙ ПРОМТ (скопируй это)

```
Я работаю над проектом Monster Exploit Scanner в /Users/sid/projects/token-vuln-scanner

Это автономный круглосуточный сканер уязвимостей смарт-контрактов.

ПРОЧИТАЙ ОБЯЗАТЕЛЬНО:
- docs/PROJECT_MEMORY.md — полная память проекта
- ROADMAP.md — планы на будущее
- AGENTS.md — инструкции для агента

БЫСТРЫЙ СТАРТ:
source .venv/bin/activate
python run_dashboard.py  # http://localhost:8000
python -m pytest --deselect tests/test_exploit_executor.py::test_no_signer_returns_false --deselect tests/test_dashboard.py

СТЕК: Python 3.12, SQLite, web3.py, Foundry, QuickNode, Etherscan V2 API

ВСЕ ОТВЕТЫ НА РУССКОМ.
```

---

## 1. АРХИТЕКТУРА

```
ПОИСК (8 слоёв × 9 цепей + 17 источников утечек)
  → ПРОВЕРКА (45 тестов + 4 API + Explorer V2 + исходники)
    → ФАЗЗИНГ (Foundry + Echidna на QuickNode форке)
      → АТАКА (Flash Loan контракт на Polygon + drain pipeline)
        → АЛЕРТ (Telegram @sobiratelka_bot + Дашборд :8000)
```

---

## 2. ВСЕ ПРОЦЕССЫ (28)

| # | Файл | Что делает | Режим |
|---|------|-----------|-------|
| 1-9 | `monster_scanner.py` ×9 | Главный сканер, 8 слоёв, loop | observe |
| 10-11 | `predator.py` ×2 | Мемпул + PairCreated, Eth+Poly | observe |
| 12 | `run_drain_scanner.py` | Фоновый drain-сканер | observe |
| 13 | `solana_predator.py` | Solana монитор (RugCheck) | observe |
| 14 | `leaked_key_hunter.py` | 17 источников утечек | 5 мин цикл |
| 15 | `github_scout.py` | Pre-release аудит | 3 часа цикл |
| 16 | `defillama_auditor.py` | Аудит протоколов | 6 часов цикл |
| 17 | `create2_hunter.py` | Metamorphic контракты | Ethereum |
| 18 | `deploy_frontrunner.py` | Фронтран деплоя | Ethereum |
| 19 | `governance_sniper.py` | DAO Timelock монитор | Ethereum |
| 20 | `storage_fisher.py` | Ключи в storage слотах | 10 мин цикл |
| 21 | `testnet_farmer.py` | Тестнет-фермер | Monad |
| 22-23 | `protocol_hunter.py` ×2 | Новые DeFi протоколы | Eth+Base |
| 24 | `key_monitor.py` | Проверка 11k+ ключей | 30 мин цикл |
| 25 | `immunefi_auditor.py` | Immunefi авто-аудитор | watch |
| 26 | `run_dashboard.py` | Дашборд | :8000 |
| 27 | `flash_auto.py` | **Flash Loan атаки** | 30 сек цикл 🆕 |
| 28 | `anvil` | Локальный форк | localhost:8545 |

---

## 3. СЛОИ ПОИСКА (Monster Scanner)

| # | Слой | Источник | Сколько |
|---|------|----------|---------|
| 1 | CoinGecko | API токенов | 300 |
| 2 | Uniswap V2 | PairCreated события | 200 |
| 3 | Blockscout | Свежие контракты | ~50 |
| 4 | Transfer Events | Активные адреса | 200 |
| 5 | Known Targets | Мосты,CEX,DeFi | ~17 |
| 6 | Sushi/PancakeSwap | Ещё DEX пары | 400 |
| 7 | MEV Searchers | Сэндвич-боты | ~10 |
| 8 | NFT/ERC-4337 | Маркетплейсы | ~10 |

**Цепи:** Ethereum, Polygon, Arbitrum, Base, BSC, Optimism, Avalanche, Linea, Scroll, Solana

---

## 4. ПРОВЕРКИ (45)

### Байткод (32 базовых)
withdraw, mint, burn, ownership, proxy, upgrade, initialize, sweep, selfdestruct_param, uninitialized_proxy, reentrancy, honeypot, supply, permit, hidden_selfdestruct, delegatecall, cross_contract, scam_deployer, multi_send, verification, supply_concentration, liquidity_burn, deployer_risk, supply_change, bytecode_selfdestruct, bytecode_delegatecall, bytecode_sstore, cross_contract, historical, storage_layout, sandwich_flash, evmole_discovery, cross_contract_reentrancy

### Опкоды (5)
opcode_selfdestruct, opcode_delegatecall_inject, opcode_unchecked_call, opcode_timestamp_dependency, opcode_extcodesize_bypass

### Новые (5)
permit_max_allowance, amm_skim_sync, delegatecall_injection, signature_replay, multicall_unchecked

### Storage + ERC20 (2)
proxy_storage_collision, unchecked_erc20_return

### Selector Fuzzer (1)
selector_fuzz — 80+ селекторов

---

## 5. API ОБОГАЩЕНИЯ (4)

| API | Что даёт |
|-----|----------|
| DexScreener | Цена, объём, ликвидность |
| GoPlus | Honeypot, dangerous rights |
| RugCheck | Solana: authorities |
| Honeypot.is | Симуляция продажи |

---

## 6. ИСТОЧНИКИ УТЕЧЕК (17)

GitHub code, GitHub Gists, Pastebin, Sourcegraph, Reddit, GitLab, Docker Hub, StackExchange, Hastebin, Web .env, NPM, Wayback Machine, Dev.to, Shodan (placeholder)

Ищет: приватники (64 hex), seed-фразы (12/24 BIP39), API ключи Infura/Alchemy

---

## 7. ФАЗЗИНГ

| Инструмент | Тип | Итерации | Где |
|-----------|-----|----------|-----|
| Foundry | Stateless | 100k/тест | `fuzz/foundry/` |
| Echidna | Stateful | 10k/тест | Docker |
| Python | Multi-step | 500/тест | `invariant_fuzzer.py` |

Форк: QuickNode ($0/мес) → Anvil localhost:8545

---

## 8. FLASH LOAN СИСТЕМА 🆕

### Контракт
- Адрес: `0x0B8579e155C432fF36C6C2eDF87B95F0B8DFF170` на Polygon
- Файл: `fuzz/foundry/src/FlashLoan.sol` (FlashAttack)
- Aave V3 → QuickSwap → SushiSwap → repay → profit

### Авто-атаки
- Файл: `flash_auto.py`
- Каждые 30 секунд: поиск токенов с ликвидностью $500-$8000
- Если спред >1.5% → `FlashAttack.go(token, $5000)`
- Профит на кошелёк

### Кошелёк
- Адрес: `0xaA83AD23Fc48a72e4810cc26E7D58E41a1D1eC5A`
- Баланс: ~49.6 MATIC
- Приватник в `config.toml`

---

## 9. КЛЮЧИ И ДОСТУПЫ

| Что | Значение |
|-----|----------|
| Сигнер Polygon | `0xaA83AD23Fc48a72e4810cc26E7D58E41a1D1eC5A` |
| Приватник | `<скрыто — в config.toml>` |
| Etherscan API | `<скрыто — в config.toml>` |
| GitHub Token | `<скрыто — в config.toml>` |
| QuickNode | `icy-prettiest-hexagon.ethereum-mainnet.quiknode.pro/...` |
| Telegram Bot | `<скрыто — в config.toml>` @sobiratelka_bot |
| Telegram Chat | `<скрыто — в config.toml>` |

### RPC (публичные, без лимитов)
- Ethereum: `ethereum-rpc.publicnode.com`
- Polygon: `polygon-bor.publicnode.com`
- Arbitrum: `arb1.arbitrum.io`
- Base: `mainnet.base.org`
- BSC: `bsc-dataseed.binance.org`

---

## 10. БАЗА ДАННЫХ

`scanner.db` (SQLite)
- `contract_targets`: 130k+ контрактов
- `findings_log`: логи находок
- `pending_tokens`: токены в обработке

---

## 11. ДАШБОРД

http://localhost:8000
- 3 таба: Обзор / Процессы / Находки
- Автообновление 60с
- Вердикты на русском
- Flash Loan статус

---

## 12. СТРУКТУРА ФАЙЛОВ

```
token-vuln-scanner/
├── monster_scanner.py      # Главный сканер (8 слоёв)
├── predator.py             # Мемпул + PairCreated
├── leaked_key_hunter.py    # 17 источников утечек
├── github_scout.py         # Pre-release GitHub аудит
├── defillama_auditor.py    # DefiLlama протоколы
├── flash_auto.py           # Flash Loan авто-атаки 🆕
├── flash_attacker.py       # Flash Loan скрипт
├── key_monitor.py          # Мониторинг баланса ключей
├── storage_fisher.py       # Ключи в storage слотах
├── create2_hunter.py       # Metamorphic контракты
├── deploy_frontrunner.py   # Фронтран деплоя
├── governance_sniper.py    # DAO proposal sniper
├── protocol_hunter.py      # Новые DeFi протоколы
├── solana_predator.py      # Solana монитор
├── immunefi_auditor.py     # Immunefi авто-сканер
├── erc20_drain_hunter.py   # Поиск токенов в контрактах
├── invariant_fuzzer.py     # Python фаззер
├── monster_fuzz_bridge.py  # Мост сканер→фаззер
├── testnet_farmer.py       # Тестнет-фермер
├── run_dashboard.py        # Дашборд
├── run_drain_scanner.py    # Фоновый drain
├── zero_day.py             # Zero-day фаззер
├── deep_hunter.py          # Мосты+MEV+L2 сканер
├── max_scanner.py          # Мульти-векторный сканер
├── pair_sniper.py          # Снайпинг UniV2 пар
├── pumpfun_sniper.py       # Pump.fun снайпер
├── echidna_all.py          # Echidna на все контракты
├── src/
│   ├── rpc.py              # RpcClient + MultiRpcClient
│   ├── exploit_executor.py # Drain pipeline + Flashbots
│   ├── explorer.py         # ExplorerClient V2
│   ├── abi_resolver.py     # Blockscout ABI
│   ├── signer.py           # Key loading
│   ├── utils.py            # Telegram, DB, profit gate
│   ├── scanners/checks/evm/ # 45 проверок
│   ├── enrichment/         # 4 API обогащения
│   ├── sources/            # Источники контрактов
│   └── web/                # Дашборд
├── fuzz/foundry/           # Foundry проект
│   ├── src/FlashLoan.sol   # Flash Loan контракт
│   ├── src/FlashV2.sol     # Flash V2 (4 DEX)
│   └── test/               # Fuzz тесты
├── immunefi_pages/         # Страницы Immunefi
├── docs/
│   └── PROJECT_MEMORY.md   # Память проекта
├── ROADMAP.md              # Планы
├── AGENTS.md               # Инструкции
├── config.toml             # Конфигурация
└── scanner.db              # База данных
```

---

## 13. КОМАНДЫ

```bash
# Активация
source .venv/bin/activate

# Дашборд
python run_dashboard.py  # http://localhost:8000

# Тесты
python -m pytest --deselect tests/test_exploit_executor.py::test_no_signer_returns_false --deselect tests/test_dashboard.py

# Фаззинг
cd fuzz/foundry && forge test --fork-url mainnet --fuzz-runs 50000

# Форк
anvil --fork-url https://icy-prettiest-hexagon.ethereum-mainnet.quiknode.pro/...KEY.../

# Flash Loan деплой
cd fuzz/foundry && forge create --rpc-url https://polygon-bor.publicnode.com --private-key $KEY --legacy --broadcast src/FlashLoan.sol:FlashAttack

# Запуск всех процессов
python monster_scanner.py ethereum --loop &
# ... (28 процессов — см. AGENTS.md для полного списка)
```

---

## 14. РЕЗУЛЬТАТЫ

### Что нашли
- ~100 CRITICAL паттернов → все ложные
- 11,634 приватников → все пустые
- 12 контрактов с токенами ($700-877) → royaltySplitter (не exploitable)

### Что извлекли
- $0 денег
- ~$0.15 потрачено на газ (тестовые транзакции)

### Почему
Рынок зрелый. Уязвимые контракты без денег. Деньги в аудированных контрактах. Система работает корректно — не даёт ложных drain.

---

## 15. ЧТО ДЕЛАТЬ ДАЛЬШЕ

1. Ждать — система автономна
2. Flash Loan — ждать токен с низкой ликвидностью на Polygon
3. Пополнить Polygon если 49.6 MATIC кончатся
4. Добавить Monad/Berachain при запуске mainnet
5. PolyCopy проект — копи-трейдинг для Polymarket (`/Users/sid/Desktop/PolyCopy`)
