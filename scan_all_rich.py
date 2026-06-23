"""Scan all non-Ethereum rich contracts in parallel (different RPCs)."""
import tomllib
import time
from concurrent.futures import ThreadPoolExecutor
import logging
from src.rpc import RpcClient
from src.types import TokenInfo, PoolInfo, Chain
from src.scanners.evm_scanner import EvmScanner
from src.data import DataCollector
from src.explorer import ExplorerClient
from src.verifiers.runner import VerifierRunner
from src.verifiers.honeypot import HoneypotVerifier
from src.verifiers.exploit_simulator import SimulatedExploitVerifier
from src.verifiers.multi_step import MultiStepVerifier
from decimal import Decimal

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("scan-all-rich")

CHAIN_CONFIG = {
    "base": ("rich_base.txt", Chain.BASE),
    "zksync": ("rich_zksync.txt", Chain.ZKSYNC),
}

def load_targets(path: str) -> list[tuple[str, float]]:
    targets = []
    try:
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
    except FileNotFoundError:
        pass
    return targets

def scan_chain(chain_key: str, path: str, chain: Chain, rpc_url: str):
    logger.info("=== %s: starting scan ===", chain_key.upper())
    targets = load_targets(path)
    if not targets:
        logger.info("  %s: no targets", chain_key)
        return

    rpc = RpcClient(rpc_url, max_retries=3)
    explorer = ExplorerClient()
    data = DataCollector(rpc=rpc, explorer=explorer)
    verifier_runner = VerifierRunner(verifiers=[
        HoneypotVerifier(), SimulatedExploitVerifier(), MultiStepVerifier(),
    ])
    scanner = EvmScanner(data_collector=data, rpc=rpc, verifier_runner=verifier_runner, executor=None)

    for i, (addr, known_bal) in enumerate(targets):
        try:
            raw = rpc.call("eth_getBalance", [addr, "latest"])
            bal = int(str(raw), 16) / 1e18 if raw else 0.0
        except Exception:
            bal = 0.0

        logger.info("  [%d/%d] %s %.4f (known: %.4f)", i + 1, len(targets), addr[:10], bal, known_bal)

        if bal < 0.001:
            logger.info("    SKIP — balance too low")
            continue

        token = TokenInfo(address=addr, symbol=addr[:10], chain=chain)
        pool = PoolInfo(address="", dex="direct", liquidity_usd=Decimal("0"))

        try:
            report = scanner.scan(token, pool)
        except Exception as e:
            logger.error("    Scan failed: %s", e)
            continue

        criticals = [f for f in report.findings if f.severity.name == "CRITICAL"]
        highs = [f for f in report.findings if f.severity.name == "HIGH"]
        logger.info("    Findings: %d CRITICAL, %d HIGH, %d total", len(criticals), len(highs), len(report.findings))
        for f in criticals:
            logger.info("    >> CRITICAL: %s conf=%.2f", f.check_name, f.confidence or 0)

    logger.info("=== %s: done ===", chain_key.upper())

def main():
    with open("config.toml", "rb") as f:
        config = tomllib.load(f)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = []
        for chain_key, (path, chain) in CHAIN_CONFIG.items():
            rpc_url = config["rpc"].get(chain_key, "")
            if not rpc_url:
                logger.warning("No RPC for %s", chain_key)
                continue
            futures.append(pool.submit(scan_chain, chain_key, path, chain, rpc_url))
        for fut in futures:
            try:
                fut.result()
            except Exception as e:
                logger.error("Chain worker failed: %s", e)

    logger.info("ALL CHAINS DONE")

if __name__ == "__main__":
    main()
