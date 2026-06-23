# Деплой Monster Exploit Scanner

## Вариант 1: Docker (быстрый)

```bash
# Локально или на VPS с Docker
cp config.example.toml config.toml   # заполнить ключи
docker compose up -d                 # дашборд на :8000
docker compose --profile full up -d  # дашборд + все сканеры
docker compose --profile tor up -d   # дашборд + Tor прокси
```

## Вариант 2: VPS (systemd)

```bash
# Копируем проект на сервер
rsync -avz --exclude '.git' --exclude '.venv' ./ root@ВАШ_IP:/opt/monster-scanner/

# Запускаем установку
ssh root@ВАШ_IP "cd /opt/monster-scanner && bash deploy/setup.sh"

# Запускаем процессы
ssh root@ВАШ_IP "
  systemctl start monster-dashboard
  systemctl start monster-scanner@ethereum
  systemctl start monster-scanner@polygon
  systemctl start monster-ens-sniper
  systemctl start monster-solana
"
```

## Вариант 3: Авто-деплой

```bash
bash deploy.sh root@ВАШ_IP
```

## Анонимный сервер

1. Купить VPS на **Njalla** (njalla.com) за BTC/XMR — не нужен email/паспорт
2. Задеплоить по инструкции выше
3. Включить Tor: `systemctl start tor`
4. Дашборд доступен через `.onion` — полная анонимность

## Провайдеры без KYC

| Провайдер | Цена/мес | Крипта | Локация |
|-----------|----------|--------|---------|
| Njalla | €5 | BTC, XMR | Швеция |
| FlokiNET | €6 | XMR | Румыния, Исландия |
| 1984 | €5 | BTC | Исландия |
| Privex | $5 | BTC, XMR | Швеция |
| AlexHost | €4 | BTC | Молдова |
