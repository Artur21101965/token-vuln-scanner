# Monster Exploit Scanner

Автономный круглосуточный сканер уязвимостей смарт-контрактов.

**28 процессов, 45 проверок, 9 цепей, Flash Loan на Polygon.**

## Архитектура

```
ПОИСК (8 слоёв × 9 цепей + 17 источников утечек)
  → ПРОВЕРКА (45 тестов + 4 API + Explorer V2 + исходники)
    → ФАЗЗИНГ (Foundry + Echidna на QuickNode форке)
      → АТАКА (Flash Loan контракт на Polygon + drain pipeline)
        → АЛЕРТ (Telegram @sobiratelka_bot + Дашборд :8000)
```

## Быстрый старт

```bash
# Клонирование
git clone https://github.com/Artur21101965/token-vuln-scanner.git
cd token-vuln-scanner

# Окружение
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Конфиг (создать из примера)
cp config.example.toml config.toml
# Заполнить ключи в config.toml

# Дашборд
python run_dashboard.py  # http://localhost:8000

# Тесты
python -m pytest --deselect tests/test_exploit_executor.py::test_no_signer_returns_false --deselect tests/test_dashboard.py
```

## Процессы

| # | Скрипт | Режим |
|---|--------|-------|
| 1-9 | `monster_scanner.py <chain> --loop` | Главный сканер |
| 10-11 | `predator.py <chain>` | Мемпул + PairCreated |
| 12 | `ens_sniper.py` | ENS домены 🆕 |
| 13 | `solana_predator.py` | Solana монитор 🆕 |
| 14 | `v4_hook_hunter.py` | Uniswap V4 хуки 🆕 |
| 15 | `leaked_key_hunter.py` | 17 источников утечек |
| 16 | `flash_auto.py` | Flash Loan атаки |
| 17 | `key_monitor.py` | Проверка ключей |
| 18 | `storage_fisher.py` | Ключи в storage |

Подробности: `docs/PROJECT_MEMORY.md`

## Лицензия

MIT
