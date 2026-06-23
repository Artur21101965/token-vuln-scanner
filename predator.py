"""
PREDATOR — Mempool Monitor + Zero-Day Hunter + Rug Pull Prevention

Strategy:
  1. Watch new blocks for contract creations → scan immediately → drain first
  2. Watch DEX PairCreated events → check for rug pulls → drain LP before scammer
  3. (Future) Watch mempool → detect drain txs → front-run with higher gas

Usage: python predator.py <chain> [--aggressive]
  --aggressive: actually submit drain transactions (default: observe only)
"""
import sys
import tomllib
import logging
import time
import json
from decimal import Decimal
from typing import Optional
import threading
import queue

from eth_utils import keccak
import websocket

from src.rpc import RpcClient
from src.types import TokenInfo, PoolInfo, Chain, Severity, Finding
from src.scanners.evm_scanner import EvmScanner
from src.data import DataCollector
from src.explorer import ExplorerClient
from src.verifiers.runner import VerifierRunner
from src.verifiers.honeypot import HoneypotVerifier
from src.verifiers.exploit_simulator import SimulatedExploitVerifier
from src.verifiers.multi_step import MultiStepVerifier
from src.exploit_executor import ExploitExecutor
from src.signer import load_evm_private_key

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [PREDATOR] %(message)s")
logger = logging.getLogger("predator")
logger.setLevel(logging.INFO)

CHAIN_MAP = {c.name.lower(): c for c in Chain}

# Quick rug-pull detection selectors (checked first, before full scan)
RUG_SELECTORS = {
    "40c10f19": "mint(address,uint256)",     # anyone can mint?
    "62b99d75": "mint()",
    "f2fde38b": "transferOwnership(address)",  # anyone can take ownership?
    "13af4035": "setOwner(address)",
    "2e1a7d4d": "withdraw(uint256)",           # anyone can withdraw?
    "3ccfd60b": "withdraw()",
    "85cf57e3": "sweep()",                     # anyone can sweep tokens?
    "ecf708a4": "sweep()",
    "8456cb59": "pause()",                     # can toggle trading?
    "3f4ba83a": "unpause()",
    "e2b8a209": "setFeePercent(uint256)",      # can set 100% fee?
    "9f1a54a1": "setFee(uint256)",
    "715018a6": "renounceOwnership()",
}

# DEX PairCreated topic
PAIR_CREATED_TOPIC = keccak(b"PairCreated(address,address,address,uint256)").hex()
UNI_V2_FACTORY = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"

HUNT_QUEUE: queue.Queue = queue.Queue()


# ============================================================
# Fast contract analysis (1-2 RPC calls)
# ============================================================

def quick_rug_check(rpc: RpcClient, addr: str, signer_addr: str) -> Optional[str]:
    """Fast check: is this contract immediately drainable? Returns exploit type or None."""
    code = rpc.eth_get_code(addr)
    if not code or code == "0x" or len(code) <= 4:
        return None

    code_hex = code.lower().replace("0x", "")

    # Check only selectors present in bytecode
    for sel, name in RUG_SELECTORS.items():
        if sel not in code_hex:
            continue
        try:
            gas = rpc.eth_call(addr, "0x" + sel, from_address=signer_addr)
            if gas and gas != "0x":
                return name
        except Exception:
            pass
    return None


# ============================================================
# Full scan + drain
# ============================================================

_full_scanner = None
_full_executor = None
_scan_chain = None


def init_scanner(chain: Chain, rpc: RpcClient, drain: bool):
    global _full_scanner, _full_executor, _scan_chain
    _scan_chain = chain
    explorer = ExplorerClient()
    data = DataCollector(rpc=rpc, explorer=explorer)
    verifier_runner = VerifierRunner(verifiers=[
        HoneypotVerifier(), SimulatedExploitVerifier(), MultiStepVerifier(),
    ])
    signer = load_evm_private_key()
    _full_executor = ExploitExecutor(signer=signer) if drain else None
    _full_scanner = EvmScanner(data_collector=data, rpc=rpc, verifier_runner=verifier_runner, executor=_full_executor)


def full_scan_and_drain(rpc: RpcClient, addr: str, signer_addr: str):
    """Full 33-check scan + auto-drain if vulnerable."""
    global _full_scanner, _scan_chain
    try:
        bal_raw = rpc.call("eth_getBalance", [addr, "latest"])
        bal = int(str(bal_raw), 16) / 1e18
    except Exception:
        return None

    if bal < 0.001:
        return None

    token = TokenInfo(address=addr, symbol=addr[:10], chain=_scan_chain)
    pool = PoolInfo(address="", dex="direct", liquidity_usd=Decimal("0"))

    try:
        report = _full_scanner.scan(token, pool)
    except Exception:
        return None

    criticals = [f for f in report.findings if f.severity.name == "CRITICAL"]
    return criticals


# ============================================================
# Block watcher — finds new contract creations
# ============================================================

def watch_blocks(w3_url: str, rpc_url: str, chain: Chain, aggressive: bool):
    """Layer 3: Watch new blocks for contract creations."""
    ws_url = w3_url.replace("https://", "wss://").replace("/v3/", "/ws/v3/")
    if not ws_url.startswith("wss://"):
        ws_url = w3_url.replace("http://", "ws://")

    rpc = RpcClient(rpc_url, max_retries=3)
    signer = load_evm_private_key()
    signer_addr = signer.address if signer else ""
    seen_tx: set[str] = set()

    def on_message(ws, message):
        try:
            data = json.loads(message)
            if "params" not in data:
                return
            result = data["params"]["result"]
            if not isinstance(result, dict):
                return

            block_num = int(result.get("number", "0x0"), 16)
            txs = result.get("transactions", [])

            for tx in txs:
                if isinstance(tx, str):
                    continue  # tx hash, need full receipt
                tx_hash = tx.get("hash", "")
                if tx_hash in seen_tx:
                    continue
                seen_tx.add(tx_hash)

                to_addr = tx.get("to", "")
                # Contract creation: to is null
                if not to_addr or to_addr == "0x" * 40:
                    # Get contract address from receipt
                    contract_addr = tx.get("contractAddress", "")
                    if contract_addr and contract_addr != "0x" * 40:
                        logger.info("New contract: %s (block=%d)", contract_addr[:14], block_num)
                        HUNT_QUEUE.put(("contract", contract_addr))

            # Also check all transaction recipients for interesting interactions
            for tx in txs:
                if isinstance(tx, str):
                    continue
                to_addr = tx.get("to", "")
                if to_addr and to_addr != "0x" * 40:
                    data = tx.get("input", "0x")
                    # Check if tx calls dangerous functions
                    if len(data) >= 10:
                        sel = data[2:10]
                        if sel in RUG_SELECTORS:
                            logger.info("Dangerous call: %s on %s (block=%d)",
                                        RUG_SELECTORS[sel], to_addr[:14], block_num)
                            HUNT_QUEUE.put(("dangerous_call", to_addr))

        except Exception as e:
            logger.debug("Block parse error: %s", e)

    def on_error(ws, error):
        logger.error("WS error: %s", error)

    def on_close(ws, code, msg):
        logger.warning("WS closed: %s %s. Reconnecting in 5s...", code, msg)
        time.sleep(5)
        start_block_watcher(w3_url, rpc_url, chain, aggressive)

    def on_open(ws):
        sub_msg = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "eth_subscribe",
            "params": ["newHeads"]
        })
        ws.send(sub_msg)
        logger.info("Watching blocks on %s...", chain.name)

    ws = websocket.WebSocketApp(
        ws_url,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        on_open=on_open,
    )
    ws.run_forever(ping_interval=30, ping_timeout=10)


def start_block_watcher(w3_url, rpc_url, chain, aggressive):
    threading.Thread(
        target=watch_blocks, args=(w3_url, rpc_url, chain, aggressive), daemon=True
    ).start()


# ============================================================
# DEX watcher — detects new LP pairs (rug pull targets)
# ============================================================

def watch_dex_pairs(rpc_url: str, chain: Chain):
    """Layer 4: Watch for new DEX pairs — potential rug pulls."""
    rpc = RpcClient(rpc_url, max_retries=5)
    last_block = rpc.get_block_number()

    logger.info("Watching DEX pairs from block %d...", last_block)

    while True:
        try:
            current = rpc.get_block_number()
            if current > last_block + 1000:
                current = last_block + 1000
            if current <= last_block:
                time.sleep(5)
                continue

            # Fetch PairCreated events in new blocks
            try:
                logs = rpc.get_logs(
                    hex(last_block + 1), hex(current),
                    UNI_V2_FACTORY, ["0x" + PAIR_CREATED_TOPIC]
                )
            except Exception:
                time.sleep(5)
                continue

            for log in logs:
                data = log.get("data", "")
                if len(data) >= 64:
                    pair_addr = "0x" + data[24:64]
                    if len(pair_addr) == 42:
                        logger.info("New LP pair: %s", pair_addr[:14])
                        HUNT_QUEUE.put(("pair", pair_addr))

                    token0 = "0x" + log.get("topics", ["", ""])[1][-40:] if len(log.get("topics", [])) > 1 else ""
                    token1 = "0x" + log.get("topics", ["", "", ""])[2][-40:] if len(log.get("topics", [])) > 2 else ""
                    if token0 and token0 != "0x":
                        HUNT_QUEUE.put(("token", token0))
                    if token1 and token1 != "0x":
                        HUNT_QUEUE.put(("token", token1))

            last_block = current
            time.sleep(5)

        except Exception as e:
            logger.error("DEX watcher error: %s", e)
            time.sleep(10)


# ============================================================
# Hunter — processes the queue
# ============================================================

def hunter_loop(rpc_url: str, chain: Chain, aggressive: bool):
    """Process discovered contracts: scan + drain if vulnerable."""
    rpc = RpcClient(rpc_url, max_retries=5)
    signer = load_evm_private_key()
    signer_addr = signer.address if signer else ""
    processed: set[str] = set()

    logger.info("Hunter ready (aggressive=%s)", aggressive)

    while True:
        try:
            source, addr = HUNT_QUEUE.get(timeout=30)
        except queue.Empty:
            continue

        addr_lower = addr.lower()
        if addr_lower in processed:
            continue
        processed.add(addr_lower)

        logger.info("Hunting [%s]: %s", source, addr[:14])

        try:
            bal_raw = rpc.call("eth_getBalance", [addr, "latest"])
            bal = int(str(bal_raw), 16) / 1e18
        except Exception:
            bal = 0.0

        if bal < 0.001:
            continue

        logger.info("  Balance: %.4f — scanning...", bal)

        # Quick rug check (1-2 RPC calls)
        quick = quick_rug_check(rpc, addr, signer_addr)
        if quick:
            logger.warning("  ⚠️  QUICK HIT: %s (%s) — %.4f ETH!", quick, source, bal)

        # Full scan (only for contracts with significant balance)
        if bal >= 0.01:
            criticals = full_scan_and_drain(rpc, addr, signer_addr)
            if criticals:
                for f in criticals:
                    logger.warning("  ⚠️  CRITICAL: %s conf=%.2f | %.4f ETH",
                                   f.check_name, f.confidence or 0, bal)
                if aggressive:
                    logger.warning("  >>> Aggressive mode: attempting exploit <<<")

        time.sleep(0.5)


# ============================================================
# Main
# ============================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python predator.py <chain> [--aggressive]")
        return

    chain_key = sys.argv[1].lower()
    aggressive = "--aggressive" in sys.argv

    if chain_key not in CHAIN_MAP:
        print(f"Unknown chain: {chain_key}")
        return

    with open("config.toml", "rb") as f:
        config = tomllib.load(f)

    rpc_url = config["rpc"].get(chain_key, "")
    if not rpc_url:
        print(f"No RPC for {chain_key}")
        return

    chain = CHAIN_MAP[chain_key]
    rpc = RpcClient(rpc_url, max_retries=3)

    signer = load_evm_private_key()
    signer_bal = 0
    if signer:
        try:
            raw = rpc.call("eth_getBalance", [signer.address, "latest"])
            signer_bal = int(str(raw), 16) / 1e18
        except Exception:
            pass

    logger.info("=" * 60)
    logger.info("PREDATOR — %s (aggressive=%s)", chain_key.upper(), aggressive)
    logger.info("Signer: %s | Balance: %.4f", signer.address if signer else "N/A", signer_bal)
    logger.info("=" * 60)

    init_scanner(chain, rpc, drain=aggressive)

    # Start watchers
    start_block_watcher(rpc_url, rpc_url, chain, aggressive)
    threading.Thread(target=watch_dex_pairs, args=(rpc_url, chain), daemon=True).start()

    # Main loop: hunt
    hunter_loop(rpc_url, chain, aggressive)


if __name__ == "__main__":
    main()
