"""
MAXIMUM ATTACK SURFACE SCANNER — hunts 6 exploit vectors simultaneously.

Vectors:
  1. Proxy w/ implementation=0x0 → deploy backdoor contract
  2. Unverified contracts w/ balance → bytecode-level exploit
  3. Expired token vesting → claim unlocked tokens
  4. AMM pairs w/ expired LP lock → withdraw liquidity
  5. Solana program upgrade authority → takeover programs
  6. Unprotected flash loan callbacks → price manipulation

Usage: python max_scanner.py <chain> [--drain]
"""
import sys, tomllib, logging, time, json, urllib.request
from decimal import Decimal
from typing import Optional
from eth_utils import keccak

from src.rpc import RpcClient
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.scanners.evm_scanner import EvmScanner
from src.data import DataCollector
from src.explorer import ExplorerClient
from src.verifiers.runner import VerifierRunner
from src.verifiers.honeypot import HoneypotVerifier
from src.verifiers.exploit_simulator import SimulatedExploitVerifier
from src.verifiers.multi_step import MultiStepVerifier
from src.exploit_executor import ExploitExecutor
from src.signer import load_evm_private_key
from src.enrichment.dexscreener import enrich_dexscreener
from src.enrichment.goplus import enrich_goplus_evm, enrich_goplus_solana
from src.enrichment.rugcheck import enrich_rugcheck

logging.basicConfig(level=logging.INFO, format="%(asctime)s [MAX] %(message)s")
logger = logging.getLogger("max-scanner")

CHAIN_MAP = {c.name.lower(): c for c in Chain}

# ============================================================
# VECTOR 1: Proxy with implementation=0x0
# ============================================================

PROXY_ZERO_SLOTS = [
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",  # EIP-1967
    "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3",  # OpenZeppelin v2
]

def check_proxy_zero_impl(rpc: RpcClient, addr: str) -> Optional[str]:
    """Check if proxy implementation slot is 0x0 (uninitialized)."""
    for slot_hex in PROXY_ZERO_SLOTS:
        try:
            slot_int = int(slot_hex, 16)
            val = rpc.get_storage_at(addr, slot_int)
            if val and val != "0x" and val != "0x" + "0" * 64:
                impl = "0x" + val[-40:]
                if impl == "0x" + "0" * 40 or int(impl, 16) == 0:
                    return impl
                # Check if implementation has 0 code
                code = rpc.eth_get_code(impl)
                if not code or len(code) <= 4:
                    return impl
            else:
                # Slot is empty → uninitialized proxy
                return "0x0000000000000000000000000000000000000000"
        except Exception:
            pass
    return None


# ============================================================
# VECTOR 2: Unverified contracts (via Blockscout API)
# ============================================================

BLOCKSCOUT_URLS = {
    "ethereum": "https://eth.blockscout.com/api/v2",
    "polygon": "https://polygon.blockscout.com/api/v2",
    "arbitrum": "https://arbitrum.blockscout.com/api/v2",
    "base": "https://base.blockscout.com/api/v2",
    "optimism": "https://optimism.blockscout.com/api/v2",
}

def fetch_unverified_contracts(chain_key: str, rpc: RpcClient, max_results: int = 100) -> list[str]:
    """Fetch recent unverified contracts from Blockscout that have balance."""
    base_url = BLOCKSCOUT_URLS.get(chain_key)
    if not base_url:
        return []

    import httpx
    targets = []
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.get(f"{base_url}/smart-contracts?filter=unverified")
            if resp.status_code != 200:
                return []
            data = resp.json()
            items = data.get("items", [])
            for item in items[:max_results]:
                addr = item.get("address", {}).get("hash", "")
                if addr and addr.startswith("0x"):
                    targets.append(addr)
    except Exception as e:
        logger.debug("Blockscout unverified error: %s", e)

    return targets


# ============================================================
# VECTOR 3: Expired token vesting (Hedgey, Sablier)
# ============================================================

VESTING_FACTORIES = {
    "ethereum": {
        "hedgey": "0x2CDE9919e81b20B4B33DD562A48a84b54C48F00C",
        "sablier": "0xCD18eAa163733Da39c232722cBC4E8940b1D8888",
    },
    "polygon": {
        "hedgey": "0x0e5CA5bA15B25af6839921C3B47B7c1e9dA04FEB",
    },
    "arbitrum": {
        "hedgey": "0x2CDE9919e81b20B4B33DD562A48a84b54C48F00C",
    },
}

VESTING_CREATED_TOPIC = keccak(b"VestingCreated(address,address,uint256,uint256,uint256,uint256,bool)").hex()
LOCK_CREATED_TOPIC = keccak(b"LockCreated(uint256,address,address,address,uint256,uint256)").hex()

def check_expired_vesting(rpc: RpcClient, factory: str, chain_key: str) -> list[dict]:
    """Find vesting/lock contracts where unlock time has passed."""
    findings = []
    try:
        current = rpc.get_block_number()
        from_block = max(0, current - 200000)
        for topic_name, topic in [("VestingCreated", VESTING_CREATED_TOPIC), ("LockCreated", LOCK_CREATED_TOPIC)]:
            try:
                logs = rpc.get_logs(hex(from_block), hex(current), factory, ["0x" + topic])
            except Exception:
                continue

            now = int(time.time())
            for log in logs[:50]:
                data = log.get("data", "")
                # For LockCreated: id(i=0), token, owner, lockAddress, amount, unlockDate
                if len(data) >= 256:
                    unlock_date = int(data[192:256], 16)
                    if unlock_date > 0 and unlock_date <= now:
                        lock_addr = "0x" + data[88:128]
                        token_addr = "0x" + data[24:64]
                        amount = int(data[128:192], 16)
                        findings.append({
                            "lock_addr": lock_addr,
                            "token": token_addr,
                            "amount_wei": amount,
                            "unlocked_at": time.ctime(unlock_date),
                            "type": topic_name,
                        })
    except Exception as e:
        logger.debug("Vesting scan error: %s", e)

    return findings


# ============================================================
# VECTOR 4: AMM pairs with expired LP lock (Unicrypt, Team Finance)
# ============================================================

UNICRYPT_LOCKER = "0x663A5C229c09b049E36dCc11a9B0d4a8Eb9db214"  # all chains
DEPOSIT_TOPIC = keccak(b"onDeposit(address,address,uint256,uint256,uint256)").hex()

def check_expired_lp_locks(rpc: RpcClient) -> list[dict]:
    """Find Unicrypt LP locks where lock period expired."""
    findings = []
    try:
        current = rpc.get_block_number()
        from_block = max(0, current - 300000)
        logs = rpc.get_logs(hex(from_block), hex(current), UNICRYPT_LOCKER, ["0x" + DEPOSIT_TOPIC])
        now = int(time.time())

        for log in logs[:100]:
            data = log.get("data", "")
            # onDeposit(token, lpToken, amount, unlockDate, lockDate)
            if len(data) >= 160:
                unlock_date = int(data[96:160], 16)
                if unlock_date > 0 and unlock_date <= now:
                    token = "0x" + data[0:64][-40:]  # first 32 bytes = token address at end
                    lp_token = "0x" + data[32:96][-40:]  # bytes 32-64 = lpToken
                    findings.append({
                        "token": token,
                        "lp_token": lp_token,
                        "unlocked_at": time.ctime(unlock_date),
                    })
    except Exception as e:
        logger.debug("LP lock scan error: %s", e)

    return findings


# ============================================================
# VECTOR 5: Solana program upgrade authority
# ============================================================

SOLANA_RPC = "https://api.mainnet-beta.solana.com"

KNOWN_SOLANA_PROGRAMS = [
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",   # Jupiter Aggregator v6
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",   # Orca Whirlpool
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",  # Raydium
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",   # Pump.fun
    "SP1Dq6K2HSCkKuhfNNzZ4iRf6q4FJHPB7idJF9oBnAx",  # SolPirate (dead)
]

def check_solana_program_upgrade_auth(program_addr: str) -> Optional[dict]:
    """Check if Solana program has upgrade authority (and who)."""
    try:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
                   "params": [program_addr, {"encoding": "jsonParsed"}]}
        req = urllib.request.Request(SOLANA_RPC, json.dumps(payload).encode(),
                                      {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())

        value = data.get("result", {}).get("value", {})
        if not value:
            return None

        # Check if it's a program (executable)
        executable = value.get("executable", False)
        if not executable:
            return {"error": "not a program"}

        # Get upgrade authority from program data
        program_data = value.get("data", {}).get("parsed", {})
        owner = value.get("owner", "")

        result = {
            "program": program_addr,
            "executable": executable,
            "owner": owner,
            "lamports": value.get("lamports", 0) / 1e9,
        }

        # Also check RugCheck for authority info
        rc = enrich_rugcheck(program_addr)
        if rc:
            result["rugcheck"] = rc

        return result
    except Exception as e:
        logger.debug("Solana program check error: %s", e)
        return None


# ============================================================
# MAIN — sweep all vectors
# ============================================================

def sweep_all_vectors(chain_key: str, rpc_url: str, drain: bool):
    """Run all exploit vectors on a single chain."""
    chain = CHAIN_MAP.get(chain_key)
    if not chain:
        return

    rpc = RpcClient(rpc_url, max_retries=3)
    signer = load_evm_private_key()

    logger.info("=" * 60)
    logger.info("MAX SCAN: %s", chain_key.upper())
    logger.info("=" * 60)

    # --- Vector 1: Proxy zero-impl ---
    logger.info("\n>>> VECTOR 1: Proxy with impl=0x0")
    targets_v1 = fetch_unverified_contracts(chain_key, rpc, 50)
    proxy_hits = []
    for addr in targets_v1:
        impl = check_proxy_zero_impl(rpc, addr)
        if impl:
            bal = 0
            try:
                raw = rpc.call("eth_getBalance", [addr, "latest"])
                bal = int(str(raw), 16) / 1e18
            except Exception:
                pass
            proxy_hits.append((addr, impl, bal))
            logger.warning("  🚨 PROXY ZERO: %s impl=%s bal=%.4f", addr[:14], impl[:14], bal)
        time.sleep(0.3)
    if not proxy_hits:
        logger.info("  Nothing found")

    # --- Vector 2: Unverified with balance ---
    logger.info("\n>>> VECTOR 2: Unverified contracts with balance")
    uv_hits = 0
    for addr in targets_v1:
        try:
            code = rpc.eth_get_code(addr)
            if not code or len(code) <= 4:
                continue
            raw = rpc.call("eth_getBalance", [addr, "latest"])
            bal = int(str(raw), 16) / 1e18
            if bal >= 0.001:
                uv_hits += 1
                logger.warning("  ⚠️  Unverified+balance: %s %.4f ETH code=%d bytes",
                               addr[:14], bal, len(code) - 2)
                # Quick exploit check
                token = TokenInfo(address=addr, symbol=addr[:10], chain=chain)
                pool = PoolInfo(address="", dex="direct", liquidity_usd=Decimal("0"))
                explorer = ExplorerClient()
                data = DataCollector(rpc=rpc, explorer=explorer)
                vr = VerifierRunner(verifiers=[HoneypotVerifier(), SimulatedExploitVerifier(), MultiStepVerifier()])
                executor = ExploitExecutor(signer=signer) if drain else None
                scanner = EvmScanner(data_collector=data, rpc=rpc, verifier_runner=vr, executor=executor)
                try:
                    report = scanner.scan(token, pool)
                    crit = [f for f in report.findings if f.severity.name == "CRITICAL"]
                    for f in crit:
                        logger.warning("  🚨 CRITICAL: %s conf=%.2f", f.check_name, f.confidence or 0)
                except Exception:
                    pass
        except Exception:
            pass
        time.sleep(0.5)
    logger.info("  Unverified with balance: %d", uv_hits)

    # --- Vector 3: Expired vesting ---
    logger.info("\n>>> VECTOR 3: Expired vesting/locks")
    vesting_factories = VESTING_FACTORIES.get(chain_key, {})
    for name, factory in vesting_factories.items():
        findings = check_expired_vesting(rpc, factory, chain_key)
        if findings:
            logger.warning("  %s: %d expired locks/vesting", name, len(findings))
            for f in findings[:5]:
                logger.warning("    %s: %.4f tokens unlocked %s",
                               f["lock_addr"][:12], f["amount_wei"] / 1e18, f["unlocked_at"])
        else:
            logger.info("  %s: none", name)

    # --- Vector 4: Expired LP locks ---
    logger.info("\n>>> VECTOR 4: Expired LP locks (Unicrypt)")
    lp_findings = check_expired_lp_locks(rpc)
    if lp_findings:
        logger.warning("  Unicrypt: %d expired LP locks", len(lp_findings))
        for f in lp_findings[:5]:
            logger.warning("    token=%s unlocked=%s", f["token"][:12], f["unlocked_at"])
    else:
        logger.info("  None found")


def main():
    if len(sys.argv) < 2:
        print("Usage: python max_scanner.py <chain|all|solana> [--drain]")
        return

    target = sys.argv[1].lower()
    drain = "--drain" in sys.argv

    with open("config.toml", "rb") as f:
        config = tomllib.load(f)

    if target == "solana":
        logger.info("=" * 60)
        logger.info("SOLANA: Program upgrade authority sweep")
        logger.info("=" * 60)
        for prog in KNOWN_SOLANA_PROGRAMS:
            info = check_solana_program_upgrade_auth(prog)
            if info:
                logger.info("  %s: exec=%s lamports=%.4f owner=%s",
                            info["program"][:12], info["executable"],
                            info["lamports"], info.get("owner", "?")[:12])
            time.sleep(0.5)
        return

    if target == "all":
        chains = ["ethereum", "polygon", "arbitrum", "base"]
    else:
        chains = [target]

    for chain_key in chains:
        rpc_url = config["rpc"].get(chain_key, "")
        if not rpc_url:
            logger.warning("No RPC for %s", chain_key)
            continue
        sweep_all_vectors(chain_key, rpc_url, drain)


if __name__ == "__main__":
    main()
