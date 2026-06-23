"""
PNL TRACKER — отслеживает прибыль/убыток по всем цепям и Flash Loan.

Что считает:
  - Баланс кошельков (ETH, MATIC, SOL)
  - Потрачено на газ
  - Сдренировано токенов
  - Flash Loan профит/убыток

Usage: импортируется дашбордом, запускается как фоновый поток
"""
import os, json, time, logging, threading
from datetime import datetime, timezone

logger = logging.getLogger("pnl-tracker")

PNL_FILE = "pnl_state.json"
PNL_LOG = "pnl_history.jsonl"

# Адреса кошельков
WALLETS = {
    "ethereum": "0xd3c97d975bd035dba2aae2f1b8f04f3b3040a367",
    "polygon": "0xaA83AD23Fc48a72e4810cc26E7D58E41a1D1eC5A",
}

SOLANA_WALLET = "2Vk4a5GMsU8vMRqdS4MJTRPS34gRgkbxiyWrQtKeZjho"

# Цены токенов (USD, грубо)
PRICES = {
    "ETH": 3500.0,
    "MATIC": 0.45,
    "SOL": 150.0,
}

# RPC для балансов
RPC_URLS = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "polygon": "https://polygon-bor.publicnode.com",
}

# Общее состояние
_state = {
    "start_balances": {},
    "start_usd": 0.0,
    "current_balances": {},
    "current_usd": 0.0,
    "total_gas_spent": 0.0,
    "total_drained_usd": 0.0,
    "flash_profit_usd": 0.0,
    "flash_attempts": 0,
    "drain_attempts": 0,
    "last_update": "",
}
_lock = threading.Lock()


def _rpc_balance(chain: str) -> float:
    """Запрашивает баланс через MultiRpcClient."""
    try:
        from src.rpc import MultiRpcClient
        addr = WALLETS.get(chain)
        if not addr:
            return 0.0
        c = MultiRpcClient(chain=chain, max_retries=2)
        raw = c.call("eth_getBalance", [addr, "latest"])
        c.close()
        return int(raw, 16) / 1e18
    except Exception:
        return 0.0


def _sol_balance() -> float:
    """Запрашивает баланс Solana."""
    import urllib.request
    try:
        payload = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "getBalance",
            "params": [SOLANA_WALLET]
        }).encode()
        req = urllib.request.Request(
            "https://api.mainnet-beta.solana.com", payload,
            {"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            result = json.loads(r.read()).get("result", {}).get("value", 0)
        return result / 1e9
    except Exception:
        return 0.0


def load_state():
    """Загружает сохранённое состояние."""
    global _state
    if os.path.exists(PNL_FILE):
        try:
            with open(PNL_FILE) as f:
                saved = json.load(f)
            with _lock:
                _state.update(saved)
        except Exception:
            pass


def save_state():
    """Сохраняет состояние на диск."""
    with _lock:
        _state["last_update"] = datetime.now(timezone.utc).isoformat()
        with open(PNL_FILE, "w") as f:
            json.dump(_state, f, indent=2)


def get_snapshot() -> dict:
    """Возвращает текущий PNL-снимок для дашборда."""
    with _lock:
        return dict(_state)


def init_tracker():
    """Инициализирует трекер — запоминает стартовые балансы."""
    load_state()

    with _lock:
        if not _state["start_balances"]:
            eth_bal = _rpc_balance("ethereum")
            poly_bal = _rpc_balance("polygon")
            sol_bal = _sol_balance()

            _state["start_balances"] = {
                "ethereum": round(eth_bal, 6),
                "polygon": round(poly_bal, 6),
                "solana": round(sol_bal, 6),
            }
            _state["start_usd"] = round(
                eth_bal * PRICES["ETH"] +
                poly_bal * PRICES["MATIC"] +
                sol_bal * PRICES["SOL"], 2
            )
            logger.info("PNL старт: ETH=%.4f MATIC=%.4f SOL=%.4f → $%.2f",
                        eth_bal, poly_bal, sol_bal, _state["start_usd"])

        _state["current_balances"] = dict(_state["start_balances"])
        _state["current_usd"] = _state["start_usd"]

    save_state()


def update_balances():
    """Обновляет текущие балансы."""
    eth_bal = _rpc_balance("ethereum")
    poly_bal = _rpc_balance("polygon")
    sol_bal = _sol_balance()

    current_usd = (
        eth_bal * PRICES["ETH"] +
        poly_bal * PRICES["MATIC"] +
        sol_bal * PRICES["SOL"]
    )

    with _lock:
        _state["current_balances"] = {
            "ethereum": round(eth_bal, 6),
            "polygon": round(poly_bal, 6),
            "solana": round(sol_bal, 6),
        }
        _state["current_usd"] = round(current_usd, 2)

    save_state()
    logger.info("PNL: ETH=%.6f MATIC=%.4f SOL=%.4f → $%.2f (delta: $%.2f)",
                eth_bal, poly_bal, sol_bal, current_usd,
                current_usd - _state["start_usd"])


def record_flash_attempt(profit_usd: float = 0):
    """Записать попытку Flash Loan атаки."""
    with _lock:
        _state["flash_attempts"] += 1
        if profit_usd > 0:
            _state["flash_profit_usd"] = round(_state["flash_profit_usd"] + profit_usd, 2)
    _append_history("flash_attempt", {"profit_usd": profit_usd})
    save_state()


def record_drain_attempt(chain: str, amount_usd: float = 0):
    """Записать попытку дренажа."""
    with _lock:
        _state["drain_attempts"] += 1
        if amount_usd > 0:
            _state["total_drained_usd"] = round(_state["total_drained_usd"] + amount_usd, 2)
    _append_history("drain_attempt", {"chain": chain, "amount_usd": amount_usd})
    save_state()


def record_gas_spent(chain: str, amount_native: float):
    """Записать потраченный газ."""
    price = PRICES.get("ETH" if chain in ("ethereum", "arbitrum", "base", "optimism") else
                        "MATIC" if chain == "polygon" else
                        "SOL" if chain == "solana" else "ETH", 3500.0)
    usd = round(amount_native * price, 4)
    with _lock:
        _state["total_gas_spent"] = round(_state["total_gas_spent"] + usd, 4)
    _append_history("gas_spent", {"chain": chain, "amount": amount_native, "usd": usd})
    save_state()


def _append_history(event: str, data: dict):
    """Дописывает событие в историю."""
    try:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **data,
        }
        with open(PNL_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def pnl_loop(interval: int = 300):
    """Фоновый цикл обновления балансов."""
    init_tracker()
    while True:
        try:
            update_balances()
        except Exception as e:
            logger.error("PNL update error: %s", e)
        time.sleep(interval)


def start_background():
    """Запускает PNL трекер в фоновом потоке."""
    t = threading.Thread(target=pnl_loop, args=(300,), daemon=True)
    t.start()
    logger.info("PNL tracker started (каждые 5 мин)")
    return t
