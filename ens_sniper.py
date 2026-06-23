"""
ENS DOMAIN SNIPER v2 — мониторинг истекающих ENS-доменов через on-chain проверку.

Стратегия:
  1. Берёт словарь ценных имён: 3-4 симв слова, цифры, бренды (~800 имён)
  2. Для каждого — eth_call nameExpires(labelhash) на BaseRegistrar
  3. Фильтрует истекающие в ближайшие N дней
  4. Аллертит в Telegram

Источники: Ethereum RPC (eth_call, бесплатно)
Цикл: каждые 30 минут

Usage: python ens_sniper.py
"""
import sys
import os
import json
import time
import logging
import traceback
from datetime import datetime, timedelta, timezone
from typing import Optional

import urllib.request
import urllib.error
from web3 import Web3

CRASH_LOG = "logs/ens_sniper_crash.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ENS] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/ens_sniper.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("ens-sniper")
logger.setLevel(logging.INFO)

# ENS contracts
BASE_REGISTRAR = "0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85"
ETH_REGISTRAR_CONTROLLER = "0x283Af0B28c62C092C9727F1Ee09c02CA627EB7F5"

# RPC (берём из конфига или publicnode)
RPC_URLS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
]

# Словари ценных имён
WORDS_3 = {
    "ape", "art", "bet", "bid", "bit", "bot", "box", "boy", "bus",
    "cap", "car", "cat", "cup", "dao", "day", "def", "dex", "dog",
    "dot", "era", "eth", "eve", "fan", "far", "fat", "fax", "fee",
    "fit", "fix", "fly", "fox", "fun", "gap", "gas", "gem", "god",
    "guy", "hat", "hit", "hot", "hub", "hug", "ice", "ion", "jet",
    "job", "joy", "key", "kit", "lab", "law", "leg", "lid", "log",
    "lot", "low", "map", "max", "met", "mix", "mob", "mod", "nft",
    "nod", "not", "now", "odd", "oil", "one", "owl", "own", "pay",
    "pet", "pie", "pin", "pit", "pop", "pot", "pro", "pub", "raw",
    "red", "rim", "row", "run", "set", "sky", "sol", "sun", "tap",
    "tax", "tea", "tie", "tip", "toe", "top", "toy", "two", "use",
    "van", "vet", "via", "vip", "war", "web", "win", "wit", "won",
    "yes", "you", "zap", "zen", "zip", "zoo",
}

WORDS_4 = {
    "acid", "atom", "baby", "back", "bake", "ball", "band", "bank", "base",
    "bear", "beat", "bill", "bird", "bite", "blue", "boat", "bold", "bolt",
    "bond", "bone", "book", "boom", "born", "boss", "bowl", "bulk", "bull",
    "burn", "buzz", "cake", "call", "calm", "camp", "card", "care", "cash",
    "chat", "chip", "city", "clay", "clip", "club", "clue", "coal", "coat",
    "code", "coin", "cold", "come", "cook", "cool", "core", "cosm", "crew",
    "crop", "crow", "cube", "cult", "cute", "dawn", "dead", "deal", "debt",
    "deed", "deep", "deer", "demo", "disk", "dock", "dome", "done", "door",
    "dose", "dove", "drip", "drop", "drum", "dual", "duck", "dusk", "dust",
    "duty", "earn", "east", "easy", "echo", "edge", "edit", "epic", "euro",
    "evil", "exam", "exit", "face", "fact", "fair", "fake", "fall", "fame",
    "fang", "farm", "fast", "fate", "feel", "file", "fill", "film", "find",
    "fire", "firm", "fish", "flag", "flat", "flip", "flow", "foam", "fold",
    "folk", "food", "fool", "foot", "ford", "fork", "form", "fort", "free",
    "frog", "from", "fuel", "full", "fund", "fury", "fuse", "gain", "game",
    "gang", "gate", "gaze", "gear", "gift", "girl", "give", "glad", "glow",
    "glue", "goat", "goes", "gold", "golf", "gone", "good", "grab", "gray",
    "grid", "grow", "gulf", "guru", "hack", "half", "hall", "hand", "hard",
    "harm", "hawk", "head", "heal", "heat", "held", "hell", "help", "herb",
    "here", "hero", "hide", "high", "hill", "hint", "hire", "hold", "hole",
    "holy", "home", "hood", "hook", "hope", "horn", "host", "hour", "huge",
    "hunt", "hurt", "icon", "idea", "idle", "inch", "info", "into", "iron",
    "item", "jade", "jazz", "join", "joke", "jump", "jury", "just", "keen",
    "keep", "kick", "kids", "kill", "kind", "king", "kiss", "kite", "knee",
    "know", "lace", "lack", "lake", "lamp", "land", "lane", "lawn", "lead",
    "leaf", "leak", "lean", "left", "lend", "lens", "less", "liar", "lick",
    "life", "lift", "like", "limb", "lime", "line", "link", "lion", "list",
    "live", "load", "loan", "lock", "logo", "long", "look", "loop", "lord",
    "lose", "loss", "loud", "love", "luck", "luna", "lung", "lurk", "lynx",
    "made", "mail", "main", "make", "male", "mama", "many", "mark", "mars",
    "mask", "mass", "mate", "maze", "meat", "meet", "melt", "memo", "menu",
    "mild", "milk", "mill", "mind", "mine", "mint", "miss", "mode", "mojo",
    "mold", "mole", "monk", "mood", "moon", "more", "move", "much", "muse",
    "must", "myth", "name", "navy", "near", "neat", "neck", "need", "nest",
    "news", "next", "nice", "node", "none", "noon", "norm", "nose", "note",
    "nova", "nuke", "null", "oath", "obey", "open", "oval", "oven", "over",
    "pace", "pack", "page", "paid", "pain", "pair", "pale", "palm", "park",
    "part", "pass", "past", "path", "peak", "peel", "peer", "pick", "pile",
    "pill", "pine", "pink", "pipe", "plan", "play", "plea", "plot", "plug",
    "plus", "poem", "poet", "poke", "pole", "poll", "pond", "pool", "poor",
    "port", "pose", "post", "pour", "prey", "prop", "pull", "pump", "punk",
    "pure", "push", "quit", "race", "rack", "rage", "raid", "rail", "rain",
    "rank", "rare", "rate", "read", "real", "reef", "rein", "rent", "rest",
    "rice", "rich", "ride", "ring", "riot", "rise", "risk", "road", "rock",
    "role", "roll", "roof", "room", "root", "rope", "rose", "ruby", "ruin",
    "rule", "rush", "rust", "safe", "saga", "sage", "sail", "sake", "sale",
    "salt", "same", "sand", "save", "scam", "scan", "seal", "seat", "seed",
    "seek", "self", "sell", "send", "shed", "ship", "shit", "shoe", "shop",
    "show", "shut", "side", "sigh", "sign", "silk", "sing", "sink", "site",
    "size", "skin", "skip", "slim", "slot", "slow", "snap", "snow", "soap",
    "soft", "soil", "sold", "sole", "solo", "song", "soon", "soul", "spin",
    "spot", "star", "stay", "stem", "step", "stop", "such", "suit", "sure",
    "surf", "swan", "swap", "swim", "tail", "take", "tale", "talk", "tank",
    "tape", "task", "taxi", "team", "tear", "tell", "tend", "tent", "term",
    "test", "text", "than", "them", "they", "thin", "this", "tide", "tidy",
    "tile", "till", "tilt", "time", "tiny", "tire", "toad", "tone", "took",
    "tool", "tops", "torn", "tour", "town", "trap", "tree", "trek", "trim",
    "trip", "troy", "true", "tube", "tuck", "tune", "turn", "twin", "type",
    "ugly", "unit", "upon", "used", "user", "vault", "veil", "vein", "vent",
    "very", "vest", "view", "vine", "visa", "void", "volt", "vote", "wage",
    "wait", "wake", "walk", "wall", "want", "warm", "warn", "wash", "wave",
    "weak", "wear", "weed", "weep", "weld", "well", "west", "what", "when",
    "whim", "whip", "wide", "wife", "wild", "will", "wilt", "wind", "wine",
    "wing", "wink", "wire", "wise", "wish", "wolf", "wood", "wool", "word",
    "work", "worm", "wrap", "yard", "year", "your", "zeal", "zero", "zone",
    "zoom",
}

BRANDS = {
    "uniswap", "aave", "chainlink", "maker", "compound", "synthetix", "curve",
    "balancer", "sushiswap", "yearn", "convex", "lido", "rocketpool", "frax",
    "olympus", "opensea", "metamask", "polygon", "arbitrum", "optimism",
    "solana", "avalanche", "cosmos", "polkadot", "near", "celo", "algorand",
    "tezos", "cardano", "tron", "stellar", "ripple", "aptos", "sui",
    "google", "apple", "microsoft", "amazon", "facebook", "netflix", "tesla",
    "nvidia", "intel", "amd", "spotify", "uber", "airbnb", "stripe", "paypal",
    "coinbase", "binance", "robinhood",
}

DIGITS = {str(i) for i in range(1000)}  # 000-999

# Хеши для eth_call
NAME_EXPIRES_SIG = Web3.keccak(text="nameExpires(uint256)")[:4].hex()  # 0xd6e4fa86
OWNER_OF_SIG = Web3.keccak(text="ownerOf(uint256)")[:4].hex()          # 0x6352211e


def log_crash(reason: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    os.makedirs(os.path.dirname(CRASH_LOG), exist_ok=True)
    with open(CRASH_LOG, "a") as f:
        f.write(f"[{ts}] {reason}\n{traceback.format_exc()}\n\n")


def get_w3() -> Optional[Web3]:
    """Получает рабочий Web3 с fallback по RPC."""
    for url in RPC_URLS:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 15}))
            if w3.is_connected():
                block = w3.eth.block_number
                logger.debug("RPC OK: %s (block %d)", url, block)
                return w3
        except Exception:
            continue
    return None


def score_domain(name: str) -> tuple[int, str, str]:
    """Оценивает ценность домена. Возвращает (score, tier, reason)."""
    name_lower = name.lower()
    length = len(name)

    if length == 3:
        if name_lower in WORDS_3:
            return (100, "💎💎💎", "3-симв слово")
        if name.isdigit():
            return (95, "💎💎💎", "3 цифры")
        return (80, "💎💎", "3 символа")

    if length == 4:
        if name_lower in WORDS_4:
            return (85, "💎💎", "4-симв слово")
        if name.isdigit():
            return (80, "💎💎", "4 цифры")
        return (60, "💎", "4 символа")

    if name_lower in BRANDS:
        return (75, "💎💎", "бренд/проект")

    if length <= 5:
        if name_lower in WORDS_4 or name_lower in WORDS_3:
            return (50, "💎", "слово")
        return (20, "⭐", f"{length} символов")

    if name_lower in WORDS_4:
        return (30, "⭐", "словарное")
    if any(b in name_lower for b in BRANDS if len(b) >= 5):
        return (40, "⭐", "бренд внутри")

    return (5, "—", "обычный")


def build_name_list() -> list[str]:
    """Собирает список имён для проверки."""
    names = set()
    names.update(WORDS_3)
    names.update(WORDS_4)
    names.update(BRANDS)
    names.update(DIGITS)
    return list(names)


def check_domain(w3: Web3, name: str) -> Optional[dict]:
    """
    Проверяет один ENS-домен: регистратор, expiry, владелец.
    Возвращает dict или None если домен свободен/ошибка.
    """
    labelhash = Web3.keccak(text=name)

    # Проверяем expiry через nameExpires(uint256 labelhash)
    try:
        data = NAME_EXPIRES_SIG + labelhash.hex()
        result = w3.eth.call({
            "to": BASE_REGISTRAR,
            "data": "0x" + data,
        })
        expires_ts = int(result.hex(), 16)
    except Exception:
        return None

    # Если expiry=0 — домен не зарегистрирован
    if expires_ts == 0:
        return None

    expires_dt = datetime.fromtimestamp(expires_ts, tz=timezone.utc)
    now = datetime.now(timezone.utc)
    days_left = (expires_dt - now).days

    # Интересуют только истекающие в ближайшие 90 дней или уже истекшие
    if days_left > 90:
        return None

    # Проверяем владельца
    try:
        data = OWNER_OF_SIG + labelhash.hex()
        result = w3.eth.call({
            "to": BASE_REGISTRAR,
            "data": "0x" + data,
        })
        owner = "0x" + result.hex()[-40:] if len(result.hex()) >= 40 else result.hex()
    except Exception:
        owner = "unknown"

    return {
        "name": name + ".eth",
        "label": name,
        "expires_ts": expires_ts,
        "expires_dt": expires_dt,
        "days_left": days_left,
        "owner": owner,
    }


def run_scan():
    """Основной цикл сканирования."""
    w3 = get_w3()
    if not w3:
        logger.error("Нет доступных RPC")
        return

    names = build_name_list()
    logger.info("Проверяю %d имён...", len(names))

    found: list[dict] = []
    checked = 0

    for name in names:
        try:
            result = check_domain(w3, name)
            if result:
                found.append(result)
            checked += 1
            if checked % 100 == 0:
                logger.info("  Проверено: %d/%d. Найдено истекающих: %d",
                            checked, len(names), len(found))
        except Exception as e:
            logger.debug("Ошибка проверки %s: %s", name, e)

        time.sleep(0.08)  # не забиваем RPC

    logger.info("Проверено %d имён. Найдено истекающих: %d", len(names), len(found))

    if not found:
        logger.info("Нет истекающих ценных доменов.")
        return

    # Сортируем: сначала самые ценные и близкие к expiry
    scored = []
    for d in found:
        score, tier, reason = score_domain(d["label"])
        d["score"] = score
        d["tier"] = tier
        d["reason"] = reason
        scored.append(d)

    scored.sort(key=lambda x: (-x["score"], x["days_left"]))

    # Группируем: expired (<0), critical (0-7d), warning (7-30d), info (30-90d)
    expired = [d for d in scored if d["days_left"] < 0]
    critical = [d for d in scored if 0 <= d["days_left"] <= 7]
    warning = [d for d in scored if 7 < d["days_left"] <= 30]
    info = [d for d in scored if 30 < d["days_left"] <= 90]

    # Telegram алерт
    alerts_sent = 0

    try:
        from src.utils import send_alert

        # Топ-10: самые ценные истекающие
        top = scored[:10]
        top_parts = []
        for d in top:
            dl = d["days_left"]
            time_str = "ИСТЁК" if dl < 0 else f"через {dl}д"
            top_parts.append(
                f"{d['tier']} <b>{d['name']}</b>\n"
                f"  ⏰ {time_str} ({d['expires_dt'].strftime('%d.%m.%Y')})\n"
                f"  🏷️ {d['reason']} | 👤 <code>{d['owner'][:10]}...</code> | 📊 {d['score']}/100"
            )
        top_lines = "\n".join(top_parts)

        summary = (
            f"💎 <b>ENS DOMAIN SNIPER — сводка</b>\n\n"
            f"🔴 Истекли: {len(expired)}\n"
            f"🟠 Критично (0-7д): {len(critical)}\n"
            f"🟡 Внимание (7-30д): {len(warning)}\n"
            f"🟢 Наблюдение (30-90д): {len(info)}\n\n"
            f"<b>Топ-10:</b>\n{top_lines}"
        )

        send_alert(summary, "INFO")
        alerts_sent += 1
        logger.info("📢 Сводка отправлена в Telegram")

        # Критичные — отдельно если есть истекшие
        if expired:
            exp_lines = "\n".join(
                f"🚨 <b>{d['name']}</b> — истёк {abs(d['days_left'])}д назад | {d['reason']}"
                for d in expired[:10]
            )
            send_alert(f"🚨 <b>ИСТЕКШИЕ ENS ДОМЕНЫ</b> 🚨\n\n{exp_lines}", "CRITICAL")
            alerts_sent += 1

    except Exception as e:
        logger.error("Ошибка отправки алерта: %s", e)

    # Лог в файл
    with open("ens_expiring.txt", "w") as f:
        for d in scored:
            f.write(f"{d['name']} | expires={d['expires_dt'].isoformat()} | days_left={d['days_left']} | score={d['score']} | {d['reason']} | owner={d['owner']}\n")

    logger.info("Скан завершён. Алертов: %d. Файл: ens_expiring.txt", alerts_sent)


def main():
    logger.info("=" * 50)
    logger.info("ENS DOMAIN SNIPER v2")
    logger.info("  Метод: eth_call (on-chain, без Subgraph)")
    logger.info("  Целей: ~%d имён (3-4 симв + слова + бренды + 000-999)",
                len(WORDS_3) + len(WORDS_4) + len(BRANDS) + len(DIGITS))
    logger.info("  Цикл: каждые 60 минут")
    logger.info("=" * 50)

    while True:
        try:
            run_scan()
        except Exception as e:
            logger.error("Ошибка в run_scan: %s", e)
            log_crash(f"run_scan exception: {e}")

        logger.info("⏳ Следующий скан через 60 минут...")
        time.sleep(3600)


def run_with_restart():
    """Авто-восстановление при падении."""
    restart_delays = [10, 30, 60, 120, 300]
    crashes = 0

    while True:
        try:
            main()
        except KeyboardInterrupt:
            logger.info("Остановлен пользователем")
            break
        except SystemExit:
            break
        except Exception as e:
            crashes += 1
            delay = restart_delays[min(crashes - 1, len(restart_delays) - 1)]
            reason = f"Крах #{crashes} — {e}"
            logger.error("%s. Перезапуск через %ds...", reason, delay)
            log_crash(reason)
            time.sleep(delay)
        else:
            crashes = 0
            time.sleep(5)


if __name__ == "__main__":
    run_with_restart()
