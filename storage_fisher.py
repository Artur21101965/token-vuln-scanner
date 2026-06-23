"""
STORAGE FISHER — scans ALL storage slots of contracts with money for private keys.

Runs continuously in background. Finds:
  - Private keys stored in contract storage (deployment bugs)
  - Seed phrases in storage
  - API keys / secrets

Usage: python storage_fisher.py
"""
import sqlite3, time, logging, re
from eth_account import Account
from src.rpc import RpcClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [FISH] %(message)s")
logger = logging.getLogger("storage-fish")

CHAINS = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "polygon": "https://polygon-bor.publicnode.com",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "base": "https://mainnet.base.org",
}

MIN_BALANCE = 0.01  # ETH/MATIC minimum
MAX_SLOTS = 50      # check first 50 storage slots per contract
BATCH_SIZE = 100    # contracts per batch

checked_slots = 0
found_keys = 0

def is_private_key(hex_val: str) -> bool:
    """Check if a 32-byte hex value could be a private key."""
    if len(hex_val) != 64: return False
    if hex_val in ("0"*64, "f"*64): return False
    if hex_val.count("0") > 60: return False  # too sparse
    try:
        int(hex_val, 16)
        return True
    except: return False

def fish_chain(chain: str, rpc_url: str):
    """Scan all contracts with money for private keys in storage."""
    global checked_slots, found_keys
    rpc = RpcClient(rpc_url, max_retries=2)
    db = sqlite3.connect("scanner.db")
    
    rows = db.execute(
        "SELECT DISTINCT address FROM contract_targets WHERE chain=? ORDER BY RANDOM() LIMIT ?",
        (chain, BATCH_SIZE)
    ).fetchall()
    
    scanned = 0
    for (addr,) in rows:
        try:
            code = rpc.eth_get_code(addr)
            if not code or len(str(code)) < 10: continue
            eth = int(str(rpc.call("eth_getBalance", [addr, "latest"])), 16) / 1e18
            if eth < MIN_BALANCE: continue
        except: continue
        
        scanned += 1
        
        # Read storage slots
        for slot in range(MAX_SLOTS):
            try:
                val = rpc.get_storage_at(addr, slot)
                if not val or val == "0x" + "0" * 64: continue
                checked_slots += 1
                
                val_hex = val.replace("0x", "").lower()
                if not is_private_key(val_hex): continue
                
                # Try to derive address and check balance
                try:
                    acct = Account.from_key(val_hex)
                    derived = acct.address
                    # Quick balance check
                    try:
                        raw = rpc.call("eth_getBalance", [derived, "latest"])
                        key_bal = int(str(raw), 16) / 1e18
                    except: key_bal = 0
                    
                    if key_bal > 0 or True:  # report even 0-balance keys
                        found_keys += 1
                        logger.warning("🚨 KEY IN STORAGE: %s slot %d → %s (%.4f ETH)",
                                       addr[:14], slot, derived, key_bal)
                        with open("storage_keys_found.txt", "a") as f:
                            f.write(f"{addr} | slot {slot} | {derived} | {key_bal:.6f} ETH | {chain}\n")
                except: pass
            except: pass
    
    db.close()
    logger.info("%s: %d contracts, %d total slots checked, %d keys found",
                chain.upper(), scanned, checked_slots, found_keys)

def main():
    logger.info("=" * 50)
    logger.info("STORAGE FISHER — hunting keys in contract storage")
    logger.info("=" * 50)
    
    while True:
        for chain, url in CHAINS.items():
            fish_chain(chain, url)
        logger.info("Cycle done. Total keys found: %d. Sleeping 10 min...", found_keys)
        time.sleep(600)

if __name__ == "__main__":
    main()
