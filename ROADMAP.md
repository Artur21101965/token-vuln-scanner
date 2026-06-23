# Monster Exploit Scanner — Roadmap

## СДЕЛАНО (22 процесса, автономно 24/7)

### Сканирование
- [x] 45 проверок (селекторы + опкоды + storage + ERC20 + selector fuzz)
- [x] 9 EVM цепей + Solana
- [x] 8 слоёв поиска (CoinGecko, DEX, Blockscout, Events, Known, Sushi, MEV, NFT)
- [x] 4 API обогащения (DexScreener, GoPlus, RugCheck, Honeypot.is)

### Охота
- [x] Leaked Key Hunter — 13 источников (GitHub, Gists, Pastebin, Reddit и др.)
- [x] Deploy Frontrunner — мемпул, ловит деплои
- [x] Governance Sniper — мониторит DAO proposals
- [x] CREATE2 Hunter — metamorphic контракты
- [x] Solana Predator — WebSocket, новые токены
- [x] DefiLlama Auditor — 50 протоколов каждые 6ч

### Инфраструктура
- [x] Explorer V2 (Etherscan API — все цепи)
- [x] Flashbots relay (приватный мемпул)
- [x] MultiRpcClient (ротация между нодами)
- [x] Profit gate (не дренит если невыгодно)
- [x] Telegram алерты (@sobiratelka_bot)
- [x] БД логгинг (findings_log)
- [x] Дашборд :8000 (русский, автообновление)
- [x] Публичные RPC (5 цепей, без ключей, без лимитов)

### Пассивный доход
- [x] Тестнет-фермер (Monad, Berachain)
- [x] Airdrop Hunter (отслеживание дропов)

---

## В РАЗРАБОТКЕ

- [ ] Сэндвич-атаки на мемпуле (нужен капитал $200-500)
- [ ] Flash loan манипуляция оракулов (нужен капитал $1k+)
- [ ] ERC-4337 Bundler (нужен капитал $5k+)

---

## ИДЕИ НА БУДУЩЕЕ

### Нужен капитал:
- [ ] Запуск MEV-бота через Flashbots relay ($10k+)
- [ ] Стать валидатором PoS ($32 ETH)
- [ ] DEX-DEX арбитражный бот ($100-500)
- [ ] Снайпер новых токенов ($500+)

### Без капитала:
- [ ] Мониторинг баунти Immunefi → авто-проверка условий
- [ ] Auto-claimer разлоченных вестинг-токенов
- [ ] ENS domain sniper (истёкшие домены)
- [ ] ERC-6551 token-bound accounts
- [ ] Uniswap V4 hook exploitation
- [ ] Авто-подбор CREATE2 солта для коллизии адресов
- [ ] GitHub Actions майнинг (бесплатные вычисления)
- [ ] Flashbot bundle injection (атомарный drain + заметание)

### Новые цепи:
- [ ] Monad mainnet (когда запустится)
- [ ] Berachain mainnet
- [ ] Eclipse
- [ ] Abstract

### Улучшения:
- [ ] multi-RPC балансировка нагрузки
- [ ] PNL трекинг (сколько всего сдренили)
- [ ] Web UI вместо терминала
- [ ] Десктоп приложение (pywebview)
- [ ] Деплой на VPS анонимно (Njalla за XMR)
- [ ] Tor прокси для RPC (полная анонимность)

---

## Конфигурация

```
RPC: публичные ноды (publicnode.com, 1rpc.io)
Кошелёк: 0xD3c97D975bD035DbA2Aae2f1B8f04f3b3040A367
Solana: 2Vk4a5GMsU8vMRqdS4MJTRPS34gRgkbxiyWrQtKeZjho
Газ: Polygon 21.62 MATIC | Solana 0.047 SOL | Ethereum 0.003 ETH
Дашборд: http://localhost:8000
Telegram: @sobiratelka_bot
GitHub токен: <скрыто — в config.toml>
Etherscan: <скрыто — в config.toml>
```

---

## Запуск всех процессов

```bash
source .venv/bin/activate

# Monsters (9 цепей)
python monster_scanner.py ethereum --loop &
python monster_scanner.py polygon --drain --loop &
python monster_scanner.py arbitrum --loop &
python monster_scanner.py base --loop &
python monster_scanner.py bsc --loop &
python monster_scanner.py optimism --loop &
python monster_scanner.py avalanche --loop &
python monster_scanner.py linea --loop &
python monster_scanner.py scroll --loop &

# Predators
python predator.py polygon --aggressive &
python predator.py ethereum &

# Hunters
python leaked_key_hunter.py &
python create2_hunter.py ethereum --aggressive &
python governance_sniper.py &
python deploy_frontrunner.py ethereum &
python solana_predator.py --drain &

# Auditors
python defillama_auditor.py &

# Support
python run_drain_scanner.py &
python run_dashboard.py &
python testnet_farmer.py monad --auto &
```
