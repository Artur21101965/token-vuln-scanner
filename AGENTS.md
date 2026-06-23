# Monster Exploit Scanner — AGENTS.md

## Языковое правило
- Вся коммуникация — русский
- Код, логи, переменные — английский
- Комментарии в коде — русский

## Ключевые файлы
- `docs/PROJECT_MEMORY.md` — полная память проекта (читать перед изменениями)
- `ROADMAP.md` — планы на будущее, идеи
- `.venv/` — виртуальное окружение Python

## Как запустить

```bash
source .venv/bin/activate

# Все процессы (28 шт.)
python monster_scanner.py ethereum --loop &
python monster_scanner.py polygon --loop &
python monster_scanner.py arbitrum --loop &
python monster_scanner.py base --loop &
python monster_scanner.py bsc --loop &
python monster_scanner.py optimism --loop &
python monster_scanner.py avalanche --loop &
python monster_scanner.py linea --loop &
python monster_scanner.py scroll --loop &
python predator.py ethereum &
python predator.py polygon &
python run_drain_scanner.py &
python solana_predator.py &
python leaked_key_hunter.py &
python github_scout.py &
python defillama_auditor.py &
python create2_hunter.py ethereum &
python deploy_frontrunner.py ethereum &
python governance_sniper.py &
python storage_fisher.py &
python testnet_farmer.py all &
python protocol_hunter.py ethereum &
python protocol_hunter.py base &
python key_monitor.py &
python run_dashboard.py &

# Форк для фаззинга
anvil --fork-url https://icy-prettiest-hexagon.ethereum-mainnet.quiknode.pro/...KEY.../

# Тесты
python -m pytest --deselect tests/test_exploit_executor.py::test_no_signer_returns_false --deselect tests/test_dashboard.py
```

## Ключевая архитектура

```
ПОИСК (8 слоёв × 9 цепей)
  → ПРОВЕРКА (45 тестов + 4 API + Explorer V2)
    → ФАЗЗИНГ (Foundry + Echidna + Python на QuickNode форке)
      → DRAIN / АЛЕРТ (Profit gate → Flashbots → Telegram)
```

## RPC (публичные, без лимитов)
- Все 5 цепей на публичных RPC (publicnode.com, arb1.arbitrum.io, mainnet.base.org, bsc-dataseed.binance.org)
- QuickNode для форка (архивный доступ)

## Газ
- Polygon: 0.19 MATIC
- Ethereum: 0.003 ETH
- Solana: 0.047 SOL
- Все процессы в observe-режиме (не тратят газ)

## Дашборд
http://localhost:8000 — 3 таба, автообновление 60с, русский

## Безопасность
- Profit gate: не дренит если gas > balance
- Flashbots relay: приватный мемпул
- Все drain через eth_call верификацию
- 0 ложных drain за всю историю
