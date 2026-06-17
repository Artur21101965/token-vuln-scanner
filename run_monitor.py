#!/usr/bin/env python3
"""Token Vulnerability Scanner — Monitor.

Listens to DexScreener WebSocket for new token pairs and queues them for analysis.
"""
import asyncio
import logging
import tomllib
from src.db.queue import TokenQueue
from src.monitor import DexScreenerMonitor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)


def load_config(path: str = "config.toml") -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


async def main():
    config = load_config()
    queue = TokenQueue(db_path=config["analyzer"]["db_path"])
    queue.init_db()
    min_liquidity = config["monitor"]["min_liquidity_usd"]
    monitor = DexScreenerMonitor(queue=queue, min_liquidity=min_liquidity)
    await monitor.run()


if __name__ == "__main__":
    asyncio.run(main())
