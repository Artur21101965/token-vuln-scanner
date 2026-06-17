#!/usr/bin/env python3
"""Token Vulnerability Scanner — Analyzer.

Processes tokens from the SQLite queue, runs vulnerability checks,
and writes reports to the reports/ directory.

Usage:
    uv run python run_analyzer.py [profile]

Profiles:
    evm-drain-deep   — EVM chains, drain checks, retro scan, verify (default)
    evm-all-scan     — EVM chains, all checks, no retro, alert only
    solana-all-scan  — Solana only, all checks, retro scan, alert only
    solana-exploit   — Solana only, all checks, retro scan, verify
"""
import logging
import sys
import tomllib
from typing import Optional
from src.db.queue import TokenQueue
from src.db.deployer_store import DeployerStore
from src.data import DataCollector
from src.rpc import RpcClient
from src.explorer import ExplorerClient
from src.scanners.evm_scanner import EvmScanner
from src.scanners.solana_scanner import SolanaScanner
from src.reporter.json_report import JsonReporter
from src.analyzer import Analyzer
from src.types import Chain
from src.monitors.slot_monitor import SlotMonitor
from src.monitors.top_token_scanner import TopTokenScanner
from src.verifiers.runner import VerifierRunner
from src.verifiers.honeypot import HoneypotVerifier
from src.verifiers.exploit_simulator import SimulatedExploitVerifier
from src.verifiers.solana_exploit import SolanaExploitVerifier
from src.exploit_executor import ExploitExecutor
from src.abi_resolver import AbiResolver
from src.verifiers.multi_step import MultiStepVerifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("runner")

# ── Profile definitions ──────────────────────────────────────────────────────
PROFILES: dict[str, dict] = {
    "evm-drain-deep": {
        "chains": ["ethereum", "bsc", "base", "arbitrum", "polygon", "avalanche",
                   "optimism", "zksync", "linea", "scroll"],
        "discovery": ["retro"],
        "action": "verify",
    },
    "evm-all-scan": {
        "chains": ["ethereum", "bsc", "base", "arbitrum", "polygon",
                   "avalanche", "optimism", "zksync", "linea", "scroll"],
        "discovery": [],
        "action": "alert",
    },
    "solana-all-scan": {
        "chains": ["solana"],
        "discovery": ["retro"],
        "action": "alert",
    },
    "solana-exploit": {
        "chains": ["solana"],
        "discovery": ["retro"],
        "action": "verify",
    },
}

CHAIN_MAP = {
    "ethereum": Chain.ETHEREUM, "bsc": Chain.BSC, "arbitrum": Chain.ARBITRUM,
    "base": Chain.BASE, "polygon": Chain.POLYGON, "avalanche": Chain.AVALANCHE,
    "optimism": Chain.OPTIMISM, "zksync": Chain.ZKSYNC, "linea": Chain.LINEA,
    "scroll": Chain.SCROLL, "solana": Chain.SOLANA,
}


def load_config(path: str = "config.toml") -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def _build_evm_scanner(rpc_url: str, chain: Chain, explorer_key: str,
                       deployer_store: DeployerStore,
                       executor: Optional[ExploitExecutor] = None) -> tuple[EvmScanner, SlotMonitor]:
    rpc = RpcClient(rpc_url)
    explorer = ExplorerClient(api_key=explorer_key)
    data = DataCollector(rpc=rpc, explorer=explorer)
    verifier_runner = VerifierRunner(verifiers=[HoneypotVerifier(), SimulatedExploitVerifier(), MultiStepVerifier()])
    scanner = EvmScanner(data_collector=data, rpc=rpc, verifier_runner=verifier_runner,
                         deployer_store=deployer_store, executor=executor)
    slot_mon = SlotMonitor(data_collector=data, rpc=rpc, chain=chain)
    return scanner, slot_mon


def main():
    profile_name = sys.argv[1] if len(sys.argv) > 1 else "evm-drain-deep"
    profile = PROFILES.get(profile_name)
    if not profile:
        logger.error("Unknown profile: %s. Options: %s", profile_name, list(PROFILES.keys()))
        sys.exit(1)

    logger.info("Profile: %s | chains=%s discovery=%s action=%s",
                profile_name, profile["chains"], profile["discovery"], profile["action"])

    config = load_config()
    rpc_cfg = config["rpc"]
    explorer_cfg = config["explorer"]
    profile_chains = [CHAIN_MAP[c] for c in profile["chains"] if c in CHAIN_MAP]

    queue = TokenQueue(db_path=config["analyzer"]["db_path"])
    queue.init_db()

    deployer_store = DeployerStore(db_path=config["analyzer"]["db_path"])
    deployer_store.init_db()

    scanners: dict[Chain, EvmScanner | SolanaScanner] = {}
    slot_monitors: dict[Chain, SlotMonitor] = {}

    executor = ExploitExecutor() if profile["action"] == "exploit" else None

    evm_rpc_keys = {
        Chain.ETHEREUM: ("ethereum", "etherscan_key"),
        Chain.BSC: ("bsc", "bscscan_key"),
        Chain.ARBITRUM: ("arbitrum", "arbiscan_key"),
        Chain.BASE: ("base", "basescan_key"),
        Chain.POLYGON: ("polygon", "polygonscan_key"),
        Chain.AVALANCHE: ("avalanche", "snowtrace_key"),
        Chain.OPTIMISM: ("optimism", "optimistic_key"),
        Chain.ZKSYNC: ("zksync", "zksync_key"),
        Chain.LINEA: ("linea", "lineascan_key"),
        Chain.SCROLL: ("scroll", "scrollscan_key"),
    }
    for chain in profile_chains:
        if chain == Chain.SOLANA:
            sol_rpc = RpcClient(rpc_cfg["solana"])
            sol_explorer = ExplorerClient()
            sol_data = DataCollector(rpc=sol_rpc, explorer=sol_explorer)
            sol_verifier = VerifierRunner(verifiers=[SolanaExploitVerifier()])
            scanners[Chain.SOLANA] = SolanaScanner(data_collector=sol_data, rpc=sol_rpc,
                                                    verifier_runner=sol_verifier)
        else:
            entry = evm_rpc_keys.get(chain)
            if not entry:
                continue
            rpc_key, explorer_key = entry
            scanner, slot_mon = _build_evm_scanner(
                rpc_cfg[rpc_key], chain, explorer_cfg.get(explorer_key, ""),
                deployer_store, executor=executor,
            )
            scanners[chain] = scanner
            slot_monitors[chain] = slot_mon

    reporter = JsonReporter(output_dir=config["analyzer"]["reports_dir"])
    top_scanner = TopTokenScanner(queue=queue, min_liquidity=config["monitor"]["min_liquidity_usd"])
    abi_resolver = AbiResolver()

    if "retro" in profile["discovery"]:
        logger.info("Running retro bulk scan...")
        try:
            added = top_scanner.scan_retro_bulk(chains=profile_chains, max_per_chain=500)
            logger.info("Retro scan added %d tokens to queue", added)
        except Exception as e:
            logger.error("Retro scan failed: %s", e)

    analyzer = Analyzer(
        queue=queue,
        scanners=scanners,
        reporter=reporter,
        slot_monitors=slot_monitors,
        deployer_store=deployer_store,
        top_token_scanner=top_scanner,
        abi_resolver=abi_resolver,
    )
    analyzer.run(interval=config["analyzer"]["poll_interval"])


if __name__ == "__main__":
    main()
