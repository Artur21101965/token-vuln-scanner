#!/usr/bin/env python3
"""Token Vulnerability Scanner — Monitor.

Listens to DexScreener WebSocket for new token pairs with >$500 liquidity
and queues them for analysis.
"""
import asyncio
import logging
from src.db.queue import TokenQueue
from src.monitor import DexScreenerMonitor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)


async def main():
    queue = TokenQueue()
    queue.init_db()
    monitor = DexScreenerMonitor(queue=queue)
    await monitor.run()


if __name__ == "__main__":
    asyncio.run(main())
