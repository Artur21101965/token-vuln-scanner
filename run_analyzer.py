#!/usr/bin/env python3
"""Token Vulnerability Scanner — Analyzer.

Processes tokens from the SQLite queue, runs vulnerability checks,
and writes reports to the reports/ directory.
"""
import logging
import tomllib
from src.db.queue import TokenQueue
from src.data import DataCollector
from src.rpc import RpcClient
from src.explorer import ExplorerClient
from src.scanners.evm_scanner import EvmScanner
from src.scanners.solana_scanner import SolanaScanner
from src.reporter.json_report import JsonReporter
from src.analyzer import Analyzer
from src.verifiers.runner import VerifierRunner
from src.verifiers.honeypot import HoneypotVerifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)


def load_config(path: str = "config.toml") -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def main():
    config = load_config()

    queue = TokenQueue(db_path=config["analyzer"]["db_path"])
    queue.init_db()

    rpc_eth = RpcClient(config["rpc"]["ethereum"])
    rpc_bsc = RpcClient(config["rpc"]["bsc"])
    rpc_sol = RpcClient(config["rpc"]["solana"])
    explorer = ExplorerClient(
        api_key=config["explorer"].get("etherscan_key", ""),
    )
    data = DataCollector(rpc=rpc_eth, explorer=explorer)

    verifier_runner = VerifierRunner(verifiers=[HoneypotVerifier()])
    evm = EvmScanner(data_collector=data, rpc=rpc_eth, verifier_runner=verifier_runner)
    sol = SolanaScanner(data_collector=data, rpc=rpc_sol)
    reporter = JsonReporter(output_dir=config["analyzer"]["reports_dir"])

    analyzer = Analyzer(
        queue=queue,
        evm_scanner=evm,
        solana_scanner=sol,
        reporter=reporter,
    )
    analyzer.run(interval=config["analyzer"]["poll_interval"])


if __name__ == "__main__":
    main()
