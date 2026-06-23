#!/usr/bin/env python3
"""Mempool monitor — watches pending transactions for suspicious calls to known tokens."""
import logging
import os
import sys
import threading
import tomllib

sys.path.insert(0, os.path.dirname(__file__))

from src.rpc import RpcClient
from src.types import Chain
from src.monitors.mempool_monitor import MempoolMonitor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler("mempool.log"),
        logging.StreamHandler(),
    ],
)

EVM_CHAINS = [
    ("ethereum", Chain.ETHEREUM),
    ("bsc", Chain.BSC),
    ("arbitrum", Chain.ARBITRUM),
    ("base", Chain.BASE),
    ("polygon", Chain.POLYGON),
    ("avalanche", Chain.AVALANCHE),
    ("optimism", Chain.OPTIMISM),
]


def load_config(path: str = "config.toml") -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def main():
    config = load_config()
    rpc_config = config.get("rpc", {})
    threads = []

    for chain_name, chain in EVM_CHAINS:
        rpc_url = rpc_config.get(chain_name)
        if not rpc_url:
            continue
        rpc = RpcClient(rpc_url)
        monitor = MempoolMonitor(rpc=rpc, chain=chain)
        t = threading.Thread(target=monitor.run, daemon=True, name=f"mempool-{chain_name}")
        t.start()
        threads.append(t)
        logging.info("Mempool monitor started for %s", chain_name)

    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
