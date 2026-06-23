"""Scan rich Ethereum contracts with confirmed ETH balance for vulnerabilities."""
import time
import tomllib
import logging
from decimal import Decimal
from src.rpc import RpcClient
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.scanners.evm_scanner import EvmScanner
from src.data import DataCollector
from src.explorer import ExplorerClient
from src.verifiers.runner import VerifierRunner
from src.verifiers.honeypot import HoneypotVerifier
from src.verifiers.exploit_simulator import SimulatedExploitVerifier
from src.verifiers.multi_step import MultiStepVerifier
from src.signer import load_evm_private_key, get_receive_address

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("scan-rich-eth")

SCAN_DELAY = 3.0  # seconds between contracts to avoid Alchemy rate-limit

def get_balance(rpc, addr):
    try:
        raw = rpc.call("eth_getBalance", [addr, "latest"])
        if isinstance(raw, dict):
            raw = raw.get("result", "0x0")
        return int(str(raw), 16) / 1e18 if raw else 0.0
    except Exception as e:
        logger.warning("  Balance check failed for %s: %s", addr[:10], e)
        return -1.0  # -1 = error, not zero balance

def load_targets(path: str) -> list[tuple[str, float]]:
    targets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                try:
                    targets.append((parts[0], float(parts[1])))
                except ValueError:
                    targets.append((parts[0], 0.0))
    return targets

def main():
    with open("config.toml", "rb") as f:
        config = tomllib.load(f)

    rpc = RpcClient(config["rpc"]["ethereum"], max_retries=5)
    chain = Chain.ETHEREUM

    signer = load_evm_private_key()
    # No executor — signer has 0 ETH on L1, scan-only mode
    executor = None

    explorer = ExplorerClient()
    data = DataCollector(rpc=rpc, explorer=explorer)
    verifier_runner = VerifierRunner(verifiers=[
        HoneypotVerifier(), SimulatedExploitVerifier(), MultiStepVerifier(),
    ])
    scanner = EvmScanner(data_collector=data, rpc=rpc, verifier_runner=verifier_runner, executor=executor)

    targets = load_targets("rich_ethereum.txt")

    receive = get_receive_address(chain) or (signer.address if signer else "?")
    logger.info("Chain: %s | Signer: %s | Receive: %s", chain.name, signer.address if signer else "N/A", receive)
    logger.info("Loaded %d targets, scan_delay=%.1fs, retries=5", len(targets), SCAN_DELAY)

    total_eth = 0.0
    skipped_low = 0
    skipped_error = 0
    scanned = 0
    critical_hits = []

    for i, (addr, known_bal) in enumerate(targets):
        bal = get_balance(rpc, addr)
        logger.info("=" * 60)
        logger.info("[%d/%d] Scanning %s (live=%.4f ETH, known=%.4f ETH)",
                     i + 1, len(targets), addr, bal, known_bal)

        if bal < 0:  # error
            logger.info("  SKIP — RPC error (will retry on next run)")
            skipped_error += 1
            time.sleep(SCAN_DELAY)
            continue

        if bal < 0.001:
            logger.info("  SKIP — balance too low")
            skipped_low += 1
            time.sleep(SCAN_DELAY)
            continue

        total_eth += bal
        token = TokenInfo(address=addr, symbol=addr[:10], chain=chain)
        pool = PoolInfo(address="", dex="direct", liquidity_usd=Decimal("0"))

        try:
            report = scanner.scan(token, pool)
        except Exception as e:
            logger.error("  Scan failed: %s", e)
            time.sleep(SCAN_DELAY)
            continue

        scanned += 1
        criticals = [f for f in report.findings if f.severity.name == "CRITICAL"]
        highs = [f for f in report.findings if f.severity.name == "HIGH"]

        logger.info("  Findings: %d CRITICAL, %d HIGH, %d total",
                     len(criticals), len(highs), len(report.findings))

        for f in criticals:
            logger.info("  >> CRITICAL: %s conf=%.2f eth=%.4f", f.check_name, f.confidence or 0, bal)
            critical_hits.append((addr, bal, f.check_name, f.confidence or 0))

        if not criticals and not highs:
            logger.info("  Nothing interesting")

        time.sleep(SCAN_DELAY)

    logger.info("=" * 60)
    logger.info("DONE: scanned=%d skipped_low=%d skipped_error=%d total_eth=%.4f",
                 scanned, skipped_low, skipped_error, total_eth)
    if critical_hits:
        logger.info("CRITICAL HITS:")
        for addr, bal, check, conf in critical_hits:
            logger.info("  %s | %.4f ETH | %s (conf=%.2f)", addr, bal, check, conf)
    else:
        logger.info("No CRITICAL findings.")

if __name__ == "__main__":
    main()
