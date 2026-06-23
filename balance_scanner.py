"""
Balance-first scanner — finds contracts with ETH balance by scanning blocks.
Usage: uv run python3 balance_scanner.py polygon 50000000 20000
"""
import sys
import time
import tomllib
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.rpc import RpcClient
from src.types import Chain

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("balance-scan")

def load_config():
    with open("config.toml", "rb") as f:
        return tomllib.load(f)

CHAIN_MAP = {
    "ethereum": Chain.ETHEREUM, "bsc": Chain.BSC,
    "arbitrum": Chain.ARBITRUM, "base": Chain.BASE,
    "polygon": Chain.POLYGON, "avalanche": Chain.AVALANCHE,
    "optimism": Chain.OPTIMISM, "zksync": Chain.ZKSYNC,
    "linea": Chain.LINEA, "scroll": Chain.SCROLL,
}

MIN_BALANCE = 0.001

def get_balance(rpc, addr):
    try:
        raw = rpc.call("eth_getBalance", [addr, "latest"])
        if isinstance(raw, dict):
            raw = raw.get("result", "0x0")
        return int(str(raw), 16) / 1e18 if raw else 0.0
    except:
        return 0.0

def scan_block_range(rpc, chain_name, start_block, count, workers=20):
    found = []
    processed = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        fut_map = {}
        for bn in range(start_block, start_block + count):
            fut = pool.submit(rpc.call, "eth_getBlockReceipts", [hex(bn)])
            fut_map[fut] = bn
            time.sleep(0.01)

        for fut in as_completed(fut_map):
            bn = fut_map[fut]
            processed += 1
            try:
                receipts = fut.result()
                if not isinstance(receipts, list):
                    continue
                contracts = []
                for r in receipts:
                    ca = r.get("contractAddress", "")
                    if ca and ca.startswith("0x"):
                        contracts.append(ca.lower())
                if contracts:
                    for addr in contracts:
                        bal = get_balance(rpc, addr)
                        if bal >= MIN_BALANCE:
                            found.append((addr, bal, bn))
                            logger.info(">> FOUND %s | %.4f | block %d", addr[:10], bal, bn)
            except Exception as e:
                pass

            if processed % 500 == 0:
                logger.info("Progress: %d/%d, found: %d", processed, count, len(found))

    return found

def main():
    if len(sys.argv) < 4:
        print("Usage: uv run python3 balance_scanner.py <chain> <start_block> <count>")
        sys.exit(1)

    chain_name = sys.argv[1].lower()
    start_block = int(sys.argv[2])
    count = int(sys.argv[3])

    config = load_config()
    rpc_url = config["rpc"].get(chain_name, "")
    if not rpc_url:
        logger.error("No RPC for %s", chain_name)
        sys.exit(1)

    rpc = RpcClient(rpc_url)
    found = scan_block_range(rpc, chain_name, start_block, count)

    logger.info("=" * 60)
    logger.info("DONE — found %d contracts with balance >= %.4f", len(found), MIN_BALANCE)
    for addr, bal, bn in found:
        logger.info("  %s | %.4f | block %d", addr, bal, bn)

    # Save results
    if found:
        with open(f"balance_found_{chain_name}.txt", "w") as f:
            for addr, bal, bn in found:
                f.write(f"{addr} {bal} {bn}\n")
        logger.info("Saved to balance_found_%s.txt", chain_name)

if __name__ == "__main__":
    main()
