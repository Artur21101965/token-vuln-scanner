"""Batch-check ETH balance of all known contracts across chains."""
import sys
import time
import tomllib
import logging
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.rpc import RpcClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("find-balance")

MIN_BALANCE = 0.01
DEFAULT_WORKERS = 5

# Chain-specific worker limits: chains known to rate-limit get fewer workers
WORKERS: dict[str, int] = {
    "arbitrum": 5,
    "ethereum": 3,
}

def load_config():
    with open("config.toml", "rb") as f:
        return tomllib.load(f)

def get_balance(rpc, addr, retries=3):
    last_err = None
    for attempt in range(retries):
        try:
            raw = rpc.call("eth_getBalance", [addr, "latest"])
            if isinstance(raw, dict):
                error = raw.get("error")
                if error and isinstance(error, dict):
                    code = error.get("code", 0)
                    msg = str(error.get("message", ""))
                    if code == -32000 or "429" in msg or "rate limit" in msg.lower() or "too many requests" in msg.lower():
                        wait = 2 ** attempt
                        logger.debug("  Rate-limited, retry %d/%d after %ds", attempt + 1, retries, wait)
                        time.sleep(wait)
                        continue
                raw = raw.get("result", "0x0")
            return int(str(raw), 16) / 1e18 if raw else 0.0
        except Exception as e:
            last_err = e
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
    if last_err:
        raise last_err
    return 0.0

def check_chain(chain_name, rpc_url):
    rpc = RpcClient(rpc_url)
    db = sqlite3.connect("scanner.db")
    
    # Get all unique contract addresses for this chain
    rows1 = db.execute("SELECT DISTINCT address FROM contract_targets WHERE chain=?", (chain_name,)).fetchall()
    rows2 = db.execute("SELECT DISTINCT token_address FROM pending_tokens WHERE chain=?", (chain_name,)).fetchall()
    
    addresses = set(r[0].lower() for r in rows1 if r[0])
    addresses |= set(r[0].lower() for r in rows2 if r[0])
    
    if not addresses:
        logger.info("  %s: 0 addresses", chain_name)
        db.close()
        return []
    
    addrs = list(addresses)
    max_workers = WORKERS.get(chain_name, DEFAULT_WORKERS)
    logger.info("  %s: checking %d addresses with %d workers...", chain_name, len(addrs), max_workers)
    
    found = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        fut_map = {pool.submit(get_balance, rpc, a): a for a in addrs}
        for fut in as_completed(fut_map):
            addr = fut_map[fut]
            try:
                bal = fut.result()
                if bal >= MIN_BALANCE:
                    found.append((addr, bal))
                    logger.info("  >> %s: %.4f", addr[:10], bal)
            except:
                pass
    
    db.close()
    return found

def main():
    if len(sys.argv) > 1:
        chains = [sys.argv[1].lower()]
    else:
        chains = ["polygon", "ethereum", "arbitrum", "base", "bsc"]
    
    config = load_config()
    all_found = {}
    for chain in chains:
        rpc_url = config["rpc"].get(chain, "")
        if not rpc_url:
            logger.warning("No RPC for %s", chain)
            continue
        found = check_chain(chain, rpc_url)
        all_found[chain] = found
        with open(f"rich_{chain}.txt", "w") as f:
            for addr, bal in found:
                f.write(f"{addr} {bal:.6f}\n")
        logger.info("  => %d contracts with >= %.2f on %s", len(found), MIN_BALANCE, chain)
    
    total = sum(len(v) for v in all_found.values())
    logger.info("TOTAL: %d contracts with balance across all chains", total)

if __name__ == "__main__":
    main()
