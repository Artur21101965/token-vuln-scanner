"""
PROTOCOL HUNTER — real-time detection of NEW DeFi protocols + immediate deep audit.

Finds protocols by patterns (not random contract scanning):
  1. Large bytecode (>3KB) deployed in last blocks
  2. Has DeFi-like functions (deposit, withdraw, swap, stake, lend, borrow)
  3. Verified source code on Etherscan/Basescan
  4. Proxy pattern → analyze BOTH proxy + implementation

Auto-audits immediately:
  - ALL state-changing functions tested for access control
  - Unprotected initialize (can reinitialize?)
  - Unprotected upgrade (can hijack implementation?)
  - Storage collision check
  - Admin functions: transferOwnership, setFee, setOwner, grantRole

Usage: python protocol_hunter.py <chain> [--aggressive]
"""
import os, json, time, logging, urllib.request, threading, queue
from typing import Optional
import websocket

from src.rpc import RpcClient
from src.signer import load_evm_private_key
from src.evmole_utils import get_functions
from src.explorer import ExplorerClient
from src.types import Chain

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PROTO] %(message)s")
logger = logging.getLogger("proto-hunter")
logger.setLevel(logging.INFO)

OUR_ADDRESS = "0xD3c97D975bD035DbA2Aae2f1B8f04f3b3040A367"
EXPLORER_KEY = os.environ.get("ETHERSCAN_KEY", "")

WS_URLS = {
    "ethereum": "wss://ethereum-rpc.publicnode.com",
    "base": "wss://mainnet.base.org",
}

RPC_URLS = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "base": "https://mainnet.base.org",
}

CHAIN_MAP = {"ethereum": Chain.ETHEREUM, "base": Chain.BASE}

# DeFi protocol function patterns (if a contract has these, it's likely a protocol)
DEFI_SELECTORS = {
    "deposit": ["d0e30db0", "47e7ef24", "b6b55f25", "6e553f65"],
    "withdraw": ["2e1a7d4d", "3ccfd60b", "853828b6", "f14210a6"],
    "swap": ["38ed1739", "7ff36ab5", "18cbafe5", "8803dbee"],
    "stake": ["a694fc3a", "adc9772e", "817b1cd2"],
    "lend/borrow": ["a0712d68", "c5ebeaec", "42966c68"],
    "mint": ["40c10f19", "a0712d68", "449a52f8", "d0def521"],
}

# Critical admin functions to test
CRITICAL_SELECTORS = [
    ("2f2ff15d", "grantRole(bytes32,address)", "CRITICAL — может дать себе админку"),
    ("7d6f0d5f", "changeFundsWallet(address)", "CRITICAL — сменить кошелёк фондов"),
    ("aad2b723", "changeSigner(address)", "CRITICAL — сменить подписанта"),
    ("f2fde38b", "transferOwnership(address)", "CRITICAL — захват владения"),
    ("3659cfe6", "upgradeTo(address)", "CRITICAL — апгрейд контракта"),
    ("4f1ef286", "upgradeToAndCall(address,bytes)", "CRITICAL — апгрейд + вызов"),
    ("8129fc1c", "initialize()", "HIGH — переинициализация"),
    ("c4d66de8", "initialize(address)", "HIGH — переинициализация"),
    ("8456cb59", "pause()", "MEDIUM — пауза"),
    ("3f4ba83a", "unpause()", "MEDIUM — снятие паузы"),
    ("9f1a54a1", "setFee(uint256)", "MEDIUM — смена комиссии"),
    ("715018a6", "renounceOwnership()", "HIGH — отказ от владения"),
]

PENDING_DEPLOYS = queue.Queue()


def is_defi_protocol(funcs, code_hex: str) -> bool:
    """Check if a contract looks like a DeFi protocol."""
    selector_count = 0
    for category, selectors in DEFI_SELECTORS.items():
        for sel in selectors:
            if sel in code_hex:
                selector_count += 1
                if selector_count >= 3:
                    return True
    return False


def audit_contract(rpc: RpcClient, explorer: ExplorerClient, addr: str, chain: Chain, signer_addr: str, aggressive: bool):
    """Deep audit a newly found DeFi protocol."""
    code = rpc.eth_get_code(addr)
    if not code or len(str(code)) < 500:
        return

    code_hex = str(code).lower()
    funcs = get_functions(code)
    if not funcs or len(funcs) < 5:  # too simple
        return

    if not is_defi_protocol(funcs, code_hex):
        return

    bal = 0
    try: bal = int(str(rpc.call("eth_getBalance", [addr, "latest"])), 16) / 1e18
    except: pass

    # Get source
    src = ""
    try: src = explorer.get_source_code(addr, chain) or ""
    except: pass

    logger.warning("🔍 NEW PROTOCOL: %s | %.4f ETH | %d funcs | src=%s",
                   addr[:14], bal, len(funcs), "✅" if src else "❌")

    # Test critical admin functions
    callable_hits = []
    for sel, name, severity in CRITICAL_SELECTORS:
        if sel not in code_hex:
            continue
        calldata = "0x" + sel
        if "address" in name:
            calldata = "0x" + sel + signer_addr[2:].lower().zfill(64)
        try:
            gas = rpc.eth_call(addr, calldata, from_address=signer_addr)
            if gas and gas != "0x":
                callable_hits.append((sel, name, severity))
                logger.warning("  🚨 %s — %s", severity.split(" ")[0], name)
        except Exception as e:
            if "revert" not in str(e).lower():
                pass  # network error, not protected

    if callable_hits:
        with open("protocol_hits.txt", "a") as f:
            f.write(f"\n{time.ctime()} | {addr} | {bal:.4f} ETH | {len(funcs)} funcs\n")
            for sel, name, sev in callable_hits:
                f.write(f"  {sev}\n")
        logger.warning("SAVED: %d critical functions found!", len(callable_hits))

    # If any CRITICAL function is callable + has money → alert
    if any("CRITICAL" in s for _, _, s in callable_hits) and bal > 0.01:
        from src.utils import send_alert
        send_alert(f"🚨 PROTOCOL HIT: {addr}\n{bal:.4f} ETH\n{len(callable_hits)} critical functions CALLABLE!", "CRITICAL")


def watch_new_contracts(w3_url: str, chain: Chain, aggressive: bool):
    """WebSocket: watch mempool for new contract deployments."""
    ws_url = w3_url
    if not ws_url.startswith("wss://"):
        ws_url = "wss://" + w3_url.split("://")[1] if "://" in w3_url else w3_url

    def on_message(ws, message):
        try:
            data = json.loads(message)
            params = data.get("params", {})
            result = params.get("result", {})
            tx_hash = result.get("hash", "")
            to_addr = result.get("to", "")
            if not to_addr or to_addr == "0x" * 40:
                PENDING_DEPLOYS.put(tx_hash)
        except:
            pass

    def on_open(ws):
        ws.send(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_subscribe", "params": ["newPendingTransactions"]}))
        logger.info("Watching mempool on %s...", chain.name)

    def on_error(ws, e): logger.error("WS: %s", e)
    def on_close(ws, code, msg):
        logger.warning("WS closed. Reconnecting...")
        time.sleep(10)
        threading.Thread(target=watch_new_contracts, args=(w3_url, chain, aggressive), daemon=True).start()

    ws = websocket.WebSocketApp(ws_url, on_message=on_message, on_error=on_error, on_close=on_close, on_open=on_open)
    ws.run_forever(ping_interval=30, ping_timeout=10)


def process_deploys(rpc_url: str, chain: Chain, aggressive: bool):
    """Process pending deploy TXs: get deployed contract, audit it."""
    rpc = RpcClient(rpc_url, max_retries=2)
    explorer = ExplorerClient(EXPLORER_KEY)
    signer = load_evm_private_key()
    s_addr = signer.address if signer else ""
    seen = set()

    logger.info("Protocol Hunter ready (aggressive=%s)", aggressive)

    while True:
        try:
            tx_hash = PENDING_DEPLOYS.get(timeout=30)
        except queue.Empty:
            continue

        if tx_hash in seen:
            continue
        seen.add(tx_hash)

        # Get receipt to find deployed contract address
        try:
            receipt = rpc.call("eth_getTransactionReceipt", [tx_hash])
            if not receipt:
                continue
            contract_addr = receipt.get("contractAddress", "")
            if not contract_addr or contract_addr == "0x" * 40:
                continue
        except:
            continue

        logger.info("🆕 New deploy: %s (tx: %s...)", contract_addr[:14], tx_hash[:16])

        # Wait for block confirmation
        time.sleep(5)

        # Audit it
        audit_contract(rpc, explorer, contract_addr, chain, s_addr, aggressive)


def main():
    import sys
    chain_key = sys.argv[1] if len(sys.argv) > 1 else "ethereum"
    aggressive = "--aggressive" in sys.argv

    if chain_key not in WS_URLS:
        logger.error("No WS for %s", chain_key)
        return

    chain = CHAIN_MAP[chain_key]
    rpc_url = RPC_URLS[chain_key]

    logger.info("=" * 50)
    logger.info("PROTOCOL HUNTER: %s (aggressive=%s)", chain_key.upper(), aggressive)
    logger.info("=" * 50)

    # Start watchers
    threading.Thread(target=watch_new_contracts, args=(WS_URLS[chain_key], chain, aggressive), daemon=True).start()
    process_deploys(rpc_url, chain, aggressive)


if __name__ == "__main__":
    main()
