#!/usr/bin/env python3
"""Pool Monitor — watches DEX factory contracts for new pair creation events."""

import asyncio
import logging
import tomllib
from src.db.queue import TokenQueue
from src.rpc import RpcClient
from src.monitors.pool_monitor import PoolMonitor
from src.types import Chain

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)

logger = logging.getLogger(__name__)

EVM_CHAINS = {
    "ethereum": Chain.ETHEREUM,
    "bsc": Chain.BSC,
    "arbitrum": Chain.ARBITRUM,
    "base": Chain.BASE,
    "polygon": Chain.POLYGON,
    "avalanche": Chain.AVALANCHE,
    "optimism": Chain.OPTIMISM,
}


def load_config(path: str = "config.toml") -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def main():
    config = load_config()
    queue = TokenQueue(db_path=config["analyzer"]["db_path"])
    queue.init_db()

    threads = []
    for chain_name, chain in EVM_CHAINS.items():
        rpc_url = config["rpc"].get(chain_name)
        if not rpc_url:
            continue
        rpc = RpcClient(rpc_url)
        monitor = PoolMonitor(rpc=rpc, chain=chain, queue=queue)
        import threading
        t = threading.Thread(target=monitor.run, daemon=True, name=f"pool-{chain_name}")
        t.start()
        threads.append(t)
        logger.info("Pool monitor started for %s", chain_name)

    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
