# Next Phase Design — Углубление анализа

## Принцип: анонимность
Никаких регистраций на Etherscan, API-ключей, подписок. Только:
- Публичные RPC (через блокчейн-гейты)
- Blockscout (бесплатно, без ключа)
- DexScreener (бесплатно, без ключа)
- Собственные вычисления (байткод, симуляция, анализ)

---

## СРАЗУ (этот спринт)

### 1. Статический анализ байткода (bytecode -> opcodes -> patterns)
**Почему:** Самый высокий ROI. Ноль внешних запросов. Находит то, что не видно по селекторам.

**Что делает:**
- Дизассемблирует байткод в opcodes (через `pyevmasm` или свой дизассемблер)
- Ищет паттерны:
  - `SELFDESTRUCT` без проверки owner
  - `DELEGATECALL` в произвольный адрес
  - `CALL` с value без проверки
  - Нестандартные `sstore` паттерны
  - Honeypot: запрет на sell через скрытые проверки
- Флагует опасные комбинации opcodes (например, `CALLER` + `CALL` без `BALANCE` проверки)

**Файлы:**
- `src/scanners/checks/evm/bytecode_selfdestruct.py`
- `src/scanners/checks/evm/bytecode_delegatecall.py`
- `src/scanners/checks/evm/bytecode_sstore_patterns.py`
- `src/evm/disassembler.py` — модуль дизассемблера

**Не зависит от:** RPC (кроме чтения байткода), API-ключей, регистраций.

### 2. Multi-step симуляция атаки
**Сейчас:** `eth_call` одной функции.
**Надо:** Цепочка: `transferOwnership(attacker)` → `upgradeTo(malicious)` → проверка storage

**Файлы:**
- `src/verifiers/multi_step.py`

### 3. Cross-contract анализ (token → pool → sweeper)
- Найти все пулы с токеном
- Проверить router'ы на drain-функции
- Построить граф связей

**Файлы:**
- `src/analyzers/cross_contract.py`

---

## ПОТОМ

### 4. Хранилище и параллелизация
- Redis для очереди (вместо SQLite)
- Пул воркеров (asyncio / multiprocessing)
- Ретро-скан: 10+ токенов одновременно

### 5. Исторический анализ
- Парсинг Transfer-логов
- totalSupply() во времени
- Owner changes через events
- Deployer fingerprinting (gas used, timestamp patterns)

### 6. Web-дашборд
- FastAPI + HTMX (minimal, без React)
- Поиск/фильтр по токенам
- Графики: что сканируется, что найдено

### 7. Sandwich и Flash Loan детектор
- Отслеживание пулов на sandwich-атаки
- Симуляция flash loan через публичные ноды (имитация, не реальный заём)

---

## План работ

1. ✅ Mempool skip-list (WETH)
2. ✅ Deployer clustering
3. ✅ **Статический анализ байткода** (selfdestruct + delegatecall + sstore checks)
4. ✅ Multi-step симуляция
5. ✅ Cross-contract анализ (DexScreener pools + router bytecode)
6. 🔜 *инфраструктура* — хранилище (Redis), параллелизация
7. ✅ Исторический анализ (Transfer/Ownership/Upgrade события через eth_getLogs)
8. ✅ Анализ хранилища (чтение критических слотов через eth_getStorageAt)
9. ✅ Sandwich/Flash loan детектор
10. ✅ Web-дашборд (FastAPI + HTMX)
11. 🔜 *ретро-скан* — 10+ токенов одновременно
