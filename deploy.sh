#!/bin/bash
# Monster Exploit Scanner — деплой на VPS одной командой
# Использование: bash deploy.sh [user@host]

set -e

REMOTE="${1:-}"
APP="monster-scanner"
DIR="/opt/$APP"

echo "🦖 Monster Exploit Scanner — деплой"
echo "=================================="

if [ -z "$REMOTE" ]; then
    echo ""
    echo "ЛОКАЛЬНЫЙ деплой (Docker):"
    echo "  docker compose up -d"
    echo ""
    echo "УДАЛЁННЫЙ деплой:"
    echo "  bash deploy.sh root@1.2.3.4"
    echo ""
    echo "Что делает удалённый деплой:"
    echo "  1. Копирует проект на сервер в $DIR"
    echo "  2. Устанавливает Docker если нужно"
    echo "  3. Создаёт systemd-сервисы"
    echo "  4. Настраивает Tor hidden service (.onion)"
    echo "  5. Запускает всё"
    exit 0
fi

echo "► Цель: $REMOTE"
echo "► Директория: $DIR"

# 1. Копируем проект
echo "► Копирую файлы..."
rsync -avz --exclude '.git' --exclude '.venv' --exclude '*.db' \
      --exclude 'logs/' --exclude '__pycache__' \
      ./ "$REMOTE:$DIR/"

# 2. Установка и запуск
ssh "$REMOTE" bash -s << 'ENDSSH'
set -e
DIR="/opt/monster-scanner"
cd "$DIR"

# Установка Docker если нет
if ! command -v docker &>/dev/null; then
    echo "► Устанавливаю Docker..."
    curl -fsSL https://get.docker.com | sh
fi

# Создаём конфиг если нет
if [ ! -f config.toml ]; then
    echo "⚠️  config.toml не найден! Скопируй config.example.toml → config.toml и заполни ключи"
    cp config.example.toml config.toml
fi

# Docker
echo "► Билд и запуск..."
docker compose up -d --build

# Проверка
sleep 3
echo ""
echo "► Статус:"
docker compose ps
echo ""
echo "► IP: $(curl -s ifconfig.me)"
echo "► Дашборд: http://$(curl -s ifconfig.me):8000"
ENDSSH

echo ""
echo "✅ Деплой завершён!"
echo "   Дашборд: http://$REMOTE:8000"
