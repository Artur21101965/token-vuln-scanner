#!/usr/bin/env python3
"""Token Vulnerability Scanner — Analyzer.

Processes tokens from the SQLite queue, runs vulnerability checks,
and writes reports to the reports/ directory.
"""
import logging
from src.db.queue import TokenQueue
from src.data import DataCollector
from src.rpc import RpcClient
from src.explorer import ExplorerClient
from src.scanners.evm_scanner import EvmScanner
from src.scanners.solana_scanner import SolanaScanner
from src.reporter.json_report import JsonReporter
from src.analyzer import Analyzer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)


def main():
    queue = TokenQueue()
    queue.init_db()

    rpc_eth = RpcClient("https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY")
    rpc_sol = RpcClient("https://api.mainnet-beta.solana.com")
    explorer = ExplorerClient()
    data = DataCollector(rpc=rpc_eth, explorer=explorer)

    evm = EvmScanner(data_collector=data, rpc=rpc_eth)
    sol = SolanaScanner(data_collector=data, rpc=rpc_sol)
    reporter = JsonReporter()

    analyzer = Analyzer(
        queue=queue,
        evm_scanner=evm,
        solana_scanner=sol,
        reporter=reporter,
    )
    analyzer.run()


if __name__ == "__main__":
    main()
