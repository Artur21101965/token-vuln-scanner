#!/bin/bash
# Установка Monster Exploit Scanner на VPS (без Docker, systemd)
# Запускать от root на свежем сервере (Ubuntu 22.04/24.04)
# bash setup.sh

set -e

DIR="/opt/monster-scanner"
echo "🦖 Monster Exploit Scanner — установка на VPS"
echo "=============================================="

# Зависимости
echo "► Устанавливаю зависимости..."
apt-get update -qq
apt-get install -y python3.12 python3.12-venv python3-pip tor git

# Пользователь
if ! id monster &>/dev/null; then
    useradd -r -s /bin/false -d "$DIR" monster
fi

# Копируем проект (предполагается что он уже в текущей директории)
echo "► Копирую проект в $DIR..."
mkdir -p "$DIR"
cp -r ./* "$DIR/"
chown -R monster:monster "$DIR"

# venv
echo "► Создаю venv..."
sudo -u monster python3.12 -m venv "$DIR/.venv"
sudo -u monster "$DIR/.venv/bin/pip" install -r "$DIR/requirements.txt" 'httpx[socks]'

# Конфиг
if [ ! -f "$DIR/config.toml" ]; then
    cp "$DIR/config.example.toml" "$DIR/config.toml"
    echo "⚠️  Заполни $DIR/config.toml ключами!"
fi

# Логи
mkdir -p "$DIR/logs"
chown monster:monster "$DIR/logs"

# systemd
echo "► Устанавливаю systemd юниты..."
cp deploy/*.service /etc/systemd/system/
cp "$DIR/deploy"/*.service /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload

# Включаем дашборд
systemctl enable monster-dashboard
systemctl start monster-dashboard

# Tor hidden service (опционально)
if [ -f deploy/tor-hidden-service.conf ]; then
    echo "► Настраиваю Tor hidden service..."
    cat deploy/tor-hidden-service.conf >> /etc/tor/torrc
    systemctl restart tor
    sleep 3
    if [ -f /var/lib/tor/monster_scanner/hostname ]; then
        echo "   .onion: $(cat /var/lib/tor/monster_scanner/hostname)"
    fi
fi

# Фаервол
echo "► Фаервол (открываю :8000)..."
ufw allow 8000/tcp 2>/dev/null || echo "   ufw не найден, порт не открыт"

echo ""
echo "✅ Установка завершена!"
echo ""
echo "Запустить все процессы:"
echo "  systemctl start monster-dashboard"
echo "  systemctl start monster-scanner@ethereum"
echo "  systemctl start monster-scanner@polygon"
echo "  systemctl start monster-scanner@bsc"
echo "  systemctl start monster-ens-sniper"
echo "  systemctl start monster-solana"
echo "  systemctl start monster-v4-hook"
echo ""
echo "IP: $(curl -s ifconfig.me 2>/dev/null || echo '???')"
echo "Дашборд: http://$(curl -s ifconfig.me 2>/dev/null || echo '???') :8000"
