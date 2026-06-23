#!/usr/bin/env python3
"""Watches reports/ directory for new critical findings and alerts."""
import json
import os
import time
import logging
import tomllib

REPORTS_DIR = "reports"
POLL_INTERVAL = 10
ALERT_LOG = "alerts.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[
        logging.FileHandler(ALERT_LOG),
        logging.StreamHandler(),
    ],
)

EXPLORER_URLS = {
    "ethereum": "https://etherscan.io/address/",
    "bsc": "https://bscscan.com/address/",
    "arbitrum": "https://arbiscan.io/address/",
    "base": "https://basescan.org/address/",
    "polygon": "https://polygonscan.com/address/",
    "avalanche": "https://snowtrace.io/address/",
    "optimism": "https://optimistic.etherscan.io/address/",
    "zksync": "https://explorer.zksync.io/address/",
    "linea": "https://lineascan.build/address/",
    "scroll": "https://scrollscan.com/address/",
    "solana": "https://solscan.io/account/",
}

CHECK_EXPLANATIONS = {
    "mint_function_unprotected": (
        "Кто угодно может создать новые токены. "
        "Мошенник может напечатать бесконечное количество токенов "
        "и обвалить цену до нуля."
    ),
    "potential_honeypot": (
        "Токен можно купить, но нельзя продать. "
        "Создатель включил механизм, который блокирует продажи "
        "для всех, кроме себя. Твои деньги застрянут навсегда."
    ),
    "upgradeable_proxy": (
        "Контракт можно обновить (заменить программу). "
        "Если владелец не отказался от управления, он может "
        "в любой момент подменить логику токена на мошенническую."
    ),
    "selfdestruct_in_code": (
        "Контракт содержит код самоуничтожения. "
        "Кто-то может навсегда удалить контракт с блокчейна, "
        "и все токены пропадут."
    ),
    "reentrancy_call": (
        "Контракт делает внешние вызовы без защиты от повторного входа. "
        "Злоумышленник может вывести больше денег, чем положил, "
        "используя этот баг."
    ),
    "public_burn": (
        "Кто угодно может сжигать чужие токены. "
        "Любой может уничтожить твои токены без твоего разрешения."
    ),
    "permit_detected": (
        "Контракт поддерживает подпись-разрешение (permit). "
        "Фишеры могут украсть токены через поддельные подписи, "
        "если их обманом заставят подписать транзакцию."
    ),
    "unprotected_withdraw": (
        "Нашлась функция вывода средств, которую МОЖЕТ вызвать любой. "
        "Любой человек может забрать все деньги из этого контракта "
        "себе. Деньги хранить в нём опасно."
    ),
    "unprotected_approve_all": (
        "Любой может разрешить себе тратить твои токены. "
        "Злоумышленник может одним вызовом получить доступ "
        "ко всем твоим токенам."
    ),
    "public_ownership_transfer": (
        "Функцию смены владельца может вызвать кто угодно. "
        "Любой может стать владельцем контракта и забрать "
        "все деньги."
    ),
    "public_tax_update": (
        "Любой может изменить налог на покупку/продажу. "
        "Атакующий может поднять налог до 99%, "
        "и продажа станет невозможной."
    ),
    "unprotected_initialize": (
        "Функцию инициализации может вызвать кто угодно. "
        "Злоумышленник может переинициализировать контракт, "
        "назначить себя владельцем и забрать все средства."
    ),
    "unprotected_upgrade": (
        "Любой может обновить контракт до новой версии. "
        "Злоумышленник может подменить код контракта на "
        "свой собственный и украсть все деньги."
    ),
    "known_scammer_deployer": (
        "Создатель этого токена уже создавал скамы в прошлом. "
        "Высокая вероятность, что это тоже мошенничество. "
        "Не доверяй этому адресу."
    ),
    "multi_send_detected": (
        "Токен был массово разослан на множество кошельков "
        "одной транзакцией. Это типичная схема памп-дамп: "
        "сначала раздают токены, потом создают видимость спроса "
        "и продают всё сразу."
    ),
    "slot_change_detected": (
        "Системная память контракта изменилась. "
        "Кто-то мог поменять владельца или обновить логику. "
        "Проверь, не украдены ли уже деньги."
    ),
    "unverified_contract": (
        "Исходный код контракта не опубликован. "
        "Это не баг, а индикатор риска: ты не можешь проверить, "
        "что внутри. Скам-токены обычно скрывают код. "
        "Если код не виден — не вкладывай, если не доверяешь "
        "создателю лично."
    ),
    "supply_concentration": (
        "Почти все токены принадлежат одному кошельку. "
        "Владелец может в любой момент сбросить их на рынок и обвалить цену до нуля. "
        "Чем выше концентрация, тем выше риск."
    ),
    "liquidity_not_burned": (
        "Токены пула ликвидности не сожжены. "
        "Создатель может забрать всю ликвидность из пула, "
        "и ты не сможешь продать токены."
    ),
    "high_risk_deployer": (
        "Создатель этого токена уже запускал токены, "
        "в которых находили критические уязвимости. "
        "Высокая вероятность, что этот токен тоже мошеннический."
    ),
    "unprotected_mint": (
        "В контракте обнаружена функция создания новых токенов. "
        "Если она не защищена, создатель может напечатать "
        "бесконечное количество токенов в любой момент."
    ),
}

seen = set()
notifier = None


def load_config(path: str = "config.toml") -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def setup_notifier():
    global notifier
    try:
        cfg = load_config()
        tg = cfg.get("telegram", {})
        token = tg.get("bot_token", "")
        chat_id = tg.get("chat_id", "")
        if token and chat_id:
            from src.notifier.telegram import TelegramNotifier
            notifier = TelegramNotifier(bot_token=token, chat_id=chat_id)
            logging.info("Telegram notifier enabled")
    except Exception as exc:
        logging.debug("Telegram notifier setup failed: %s", exc)


def _explain_check(check_name: str) -> str:
    return CHECK_EXPLANATIONS.get(check_name, f"Подозрительная находка: {check_name}. Требуется ручная проверка.")


def _explorer_link(chain: str, address: str) -> str:
    url = EXPLORER_URLS.get(chain, "")
    if not url:
        return address[:12] + "..."
    return f'<a href="{url}{address}">{address[:12]}...</a>'


def check_reports():
    base = os.path.abspath(REPORTS_DIR)
    if not os.path.exists(base):
        return
    for chain in os.listdir(base):
        chain_dir = os.path.join(base, chain)
        if not os.path.isdir(chain_dir):
            continue
        for token_addr in os.listdir(chain_dir):
            report_path = os.path.join(chain_dir, token_addr, "report.json")
            if not os.path.exists(report_path):
                continue
            key = f"{chain}/{token_addr}"
            if key in seen:
                continue
            seen.add(key)
            with open(report_path) as f:
                data = json.load(f)
            findings = [
                f for f in data.get("findings", [])
                if f.get("details", {}).get("verified") is not False
                and f.get("details", {}).get("verification_confidence", 1.0) >= 0.9
            ]
            critical = [f for f in findings if f.get("severity") == "CRITICAL"]
            high = [f for f in findings if f.get("severity") == "HIGH"]

            if not critical and not high:
                logging.info(f"✅ {data['token']['symbol']} — чисто")
                continue

            symbol = data['token']['symbol'] or "без имени"
            chain_name = data['token']['chain']
            addr = data['token']['address']
            dex = data['pool']['dex']
            liq = data['pool']['liquidity_usd']

            # Local log — подробно
            log_msg = (
                f"\n{'='*60}\n"
                f"⚠️  НАЙДЕНА УЯЗВИМОСТЬ: {symbol} ({chain_name})\n"
                f"    Адрес: {addr}\n"
                f"    DEX: {dex} | Ликвидность: ${liq:,.0f}\n"
            )
            for f in critical + high:
                sev = "🔴 КРИТИЧЕСКАЯ" if f['severity'] == 'CRITICAL' else "🟠 ВЫСОКАЯ"
                log_msg += f"\n    [{sev}] {f['check_name']}\n"
                log_msg += f"    Что это: {_explain_check(f['check_name'])}\n"
                log_msg += f"    Детали: {f['description']}\n"
                log_msg += f"    Что делать: {f['recommendation']}\n"
            log_msg += f"\n    Полный отчёт: {report_path}\n"
            log_msg += f"{'='*60}\n"
            logging.warning(log_msg)

            # Telegram — максимально подробно, простым языком
            if notifier:
                tg_msg = (
                    f"🚨 <b>НАЙДЕНА УЯЗВИМОСТЬ В ТОКЕНЕ</b>\n\n"
                    f"<b>Токен:</b> {symbol}\n"
                    f"<b>Сеть:</b> {chain_name}\n"
                    f"<b>Адрес:</b> {_explorer_link(chain_name, addr)}\n"
                    f"<b>Биржа:</b> {dex}\n"
                    f"<b>Ликвидность:</b> ${liq:,.0f}\n"
                    f"<b>Риск:</b> {len(critical)} критических + {len(high)} высоких\n\n"
                )

                for i, f in enumerate(critical + high, 1):
                    icon = "🔴" if f['severity'] == 'CRITICAL' else "🟠"
                    level = "КРИТИЧЕСКАЯ" if f['severity'] == 'CRITICAL' else "ВЫСОКАЯ"
                    tg_msg += (
                        f"<b>{i}. {icon} {level}</b>\n"
                        f"<b>Проблема:</b> {f['check_name']}\n"
                        f"<b>Что это значит:</b> {_explain_check(f['check_name'])}\n"
                        f"<b>Подробнее:</b> {f['description']}\n"
                        f"<b>Как защититься:</b> {f['recommendation']}\n\n"
                    )

                notifier.send(tg_msg)


if __name__ == "__main__":
    setup_notifier()
    logging.info("Report watcher started")
    while True:
        try:
            check_reports()
            time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            break
        except Exception as exc:
            logging.error("Watcher error: %s", exc)
            time.sleep(POLL_INTERVAL)
