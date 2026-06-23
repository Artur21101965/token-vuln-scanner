"""
SOLANA PREDATOR — real-time new token monitor with auto-exploit.

Strategy:
  1. WebSocket logsSubscribe → catch InitializeMint instructions
  2. For each new token, check: are WE the mint/freeze authority?
  3. If YES → mint unlimited tokens → dump instantly
  4. If WE have LP → withdraw LP

Usage: python solana_predator.py [--drain]
"""
import sys
import os
import json
import time
import struct
import hashlib
import logging
import threading
import traceback
import urllib.request
from typing import Optional
import websocket

CRASH_LOG = "logs/solana_predator_crash.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SOL-PRED] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/solana_predator.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("sol-predator")
logger.setLevel(logging.INFO)

SOLANA_WS = "wss://api.mainnet-beta.solana.com"
SOLANA_RPC = "https://api.mainnet-beta.solana.com"

# Token Program ID
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

# InitializeMint instruction discriminator (first 8 bytes of sha256("global:initialize_mint"))
INIT_MINT_DISC = hashlib.sha256(b"global:initialize_mint").digest()[:8]

OUR_ADDRESS = "2Vk4a5GMsU8vMRqdS4MJTRPS34gRgkbxiyWrQtKeZjho"

BURNED = {"11111111111111111111111111111111", "So11111111111111111111111111111111111111112"}
seen_tokens: set[str] = set()
drain_enabled = False
stop_flag = False


def _load_wallet_from_config():
    """Загружает Solana-кошелёк из config.toml если есть."""
    global OUR_ADDRESS
    try:
        import tomllib
        config_path = os.path.join(os.path.dirname(__file__), "config.toml")
        if os.path.exists(config_path):
            with open(config_path, "rb") as f:
                cfg = tomllib.load(f)
            addr = cfg.get("wallet", {}).get("solana", "")
            if addr:
                OUR_ADDRESS = addr
                logger.info("Кошелёк из config.toml: %s", addr)
    except Exception:
        pass


def log_crash(reason: str):
    """Пишет причину падения в файл для отладки."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    os.makedirs(os.path.dirname(CRASH_LOG), exist_ok=True)
    with open(CRASH_LOG, "a") as f:
        f.write(f"[{ts}] {reason}\n{traceback.format_exc()}\n\n")


def rpc_call(method: str, params: list, max_retries: int = 3) -> dict:
    """Вызов Solana RPC с retry."""
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    last_error = None
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(
                SOLANA_RPC,
                json.dumps(payload).encode(),
                {"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read())
        except Exception as e:
            last_error = e
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
    raise last_error


def get_mint_account(mint_addr: str) -> Optional[dict]:
    try:
        data = rpc_call("getAccountInfo", [mint_addr, {"encoding": "jsonParsed"}])
        value = data.get("result", {}).get("value")
        if not value:
            return None
        return value.get("data", {}).get("parsed", {}).get("info", {})
    except Exception:
        return None


def check_and_exploit(mint_addr: str):
    """Check token for exploitable vulnerabilities via RugCheck + GoPlus."""
    global seen_tokens
    if mint_addr in seen_tokens:
        return
    seen_tokens.add(mint_addr)

    try:
        from src.enrichment.rugcheck import enrich_rugcheck
        from src.enrichment.goplus import enrich_goplus_solana

        rc = enrich_rugcheck(mint_addr)
        goplus = enrich_goplus_solana(mint_addr)
    except Exception as e:
        logger.error("Enrich ошибка для %s: %s", mint_addr[:8], e)
        return

    symbol = mint_addr[:8]

    if rc:
        if not rc.get("authorities_revoked", False):
            logger.warning("⚠️  %s: mint/freeze authority АКТИВНА! risks=%d score=%d",
                           symbol, rc.get("total_risks", 0), rc.get("score", 0))
            try:
                with open("solana_vulnerable.txt", "a") as f:
                    f.write(f"{mint_addr} | authorities_active | risks={rc.get('total_risks',0)} | score={rc.get('score',0)}\n")
            except Exception:
                pass

        if not rc.get("lp_locked", False):
            logger.warning("⚠️  %s: LP НЕ залочена!", symbol)

        if rc.get("is_rug", False):
            logger.info("  %s: rug history — skip", symbol)
            return

    if goplus and goplus.get("dangerous_rights", False):
        logger.warning("⚠️  %s: GoPlus — опасные права!", symbol)


def on_message(ws, message):
    try:
        data = json.loads(message)
        params = data.get("params", {})
        result = params.get("result", {})

        logs = result.get("value", {}).get("logs", [])
        if not logs:
            return

        tx_sig = result.get("value", {}).get("signature", "")
        for log_line in logs:
            if "InitializeMint" in log_line or "initialize_mint" in log_line.lower():
                if tx_sig:
                    try:
                        tx_data = rpc_call(
                            "getTransaction",
                            [tx_sig, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}],
                        )
                        tx_result = tx_data.get("result", {})
                        if not tx_result:
                            return

                        account_keys = tx_result.get("transaction", {}).get("message", {}).get("accountKeys", [])
                        for ak in account_keys:
                            addr = ak.get("pubkey", "")
                            if addr and addr != TOKEN_PROGRAM and not addr.startswith("1"):
                                info = get_mint_account(addr)
                                if info and "mintAuthority" in info:
                                    logger.info("🆕 Новый токен: %s (tx: %s)", addr[:12], tx_sig[:12])
                                    check_and_exploit(addr)
                                    break
                    except Exception as e:
                        logger.debug("TX parse error: %s", e)
                break
    except Exception as e:
        logger.debug("Message parse error: %s", e)


def on_error(ws, error):
    logger.error("WS error: %s", error)


def on_close(ws, code, msg):
    logger.warning("WS closed: code=%s msg=%s. Reconnect через 10s...", code, msg)
    time.sleep(10)
    if not stop_flag:
        start_monitor()


def on_open(ws):
    sub_msg = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "logsSubscribe",
        "params": [{"mentions": [TOKEN_PROGRAM]}],
    })
    ws.send(sub_msg)
    logger.info("🎯 Solana Predator active — monitoring Token Program")
    logger.info("   Drain: %s", "ON ⚡" if drain_enabled else "OFF 👀")
    logger.info("   Wallet: %s", OUR_ADDRESS)


def start_monitor():
    ws = websocket.WebSocketApp(
        SOLANA_WS,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        on_open=on_open,
    )
    try:
        ws.run_forever(ping_interval=30, ping_timeout=15)
    except Exception as e:
        logger.error("WS run_forever упал: %s", e)
        log_crash("WS run_forever exception")


# ---- CSV batch scanner (fallback) ----

def batch_scan_csv(csv_path: str, max_tokens: int = 100):
    """Batch scan tokens from CSV file for mint/freeze authority."""
    import csv
    try:
        with open(csv_path) as f:
            rows = [r for r in csv.DictReader(f) if 'S0' in r.get('rejection_reason', '')]
    except FileNotFoundError:
        logger.info("CSV не найден, пропускаем batch: %s", csv_path)
        return
    except Exception as e:
        logger.warning("Ошибка чтения CSV: %s", e)
        return

    logger.info("Batch scanning %d tokens from CSV...", min(len(rows), max_tokens))

    for i, row in enumerate(rows[:max_tokens]):
        try:
            addr = row.get('token_address', '')
            sym = row.get('token_symbol', '')
            if not addr:
                continue
            info = get_mint_account(addr)
            if not info:
                continue

            mint_auth = str(info.get("mintAuthority", ""))
            if mint_auth == OUR_ADDRESS:
                logger.warning("🚨 BATCH HIT: %s — мы mint authority!", sym)
                check_and_exploit(addr)

            if i % 20 == 0:
                logger.info("  Batch: %d/%d", i, min(len(rows), max_tokens))
            time.sleep(0.3)
        except Exception as e:
            logger.debug("Batch row error: %s", e)


# ---- Main ----

def main():
    global drain_enabled, stop_flag
    drain_enabled = "--drain" in sys.argv

    logger.info("=" * 50)
    logger.info("SOLANA PREDATOR v3")
    logger.info("  Drain: %s | Wallet: %s", "ON" if drain_enabled else "OFF", OUR_ADDRESS)
    logger.info("=" * 50)

    # Balance check
    try:
        bal_data = rpc_call("getBalance", [OUR_ADDRESS])
        bal = bal_data["result"]["value"] / 1e9
        logger.info("SOL balance: %.6f SOL", bal)
        if bal < 0.001 and drain_enabled:
            logger.warning("Мало SOL для газа! Нужно >0.001")
    except Exception:
        logger.warning("Не могу проверить баланс")

    # Batch scan CSV (опционально)
    csv_path = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2].endswith('.csv') else None
    if csv_path and os.path.exists(csv_path):
        threading.Thread(target=batch_scan_csv, args=(csv_path, 100), daemon=True).start()
    elif csv_path:
        logger.info("CSV не существует, пропускаем batch: %s", csv_path)

    # WebSocket monitor
    start_monitor()


# ---- Auto-restart loop ----

def run_with_restart():
    """Запускает main() в цикле с авто-восстановлением при падениях."""
    restart_delays = [5, 10, 30, 60, 120]  # экспоненциальный backoff, max 2 мин
    consecutive_crashes = 0

    while True:
        try:
            main()
        except KeyboardInterrupt:
            logger.info("Остановлен пользователем")
            break
        except SystemExit:
            break
        except Exception as e:
            consecutive_crashes += 1
            delay = restart_delays[min(consecutive_crashes - 1, len(restart_delays) - 1)]
            reason = f"Крах #{consecutive_crashes} — {e}"
            logger.error("%s. Перезапуск через %ds...", reason, delay)
            log_crash(reason)
            time.sleep(delay)
        else:
            consecutive_crashes = 0
            time.sleep(5)

    global stop_flag
    stop_flag = True


if __name__ == "__main__":
    _load_wallet_from_config()
    run_with_restart()
