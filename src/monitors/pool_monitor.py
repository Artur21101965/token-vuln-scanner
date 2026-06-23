import logging
import time
from typing import Optional
from src.rpc import RpcClient
from src.db.queue import TokenQueue
from src.monitors.factory_addresses import FACTORIES, PAIR_CREATED_TOPIC
from src.types import Chain

logger = logging.getLogger(__name__)

POLL_INTERVAL = 30  # seconds between block checks
BLOCK_RANGE = 2000  # blocks to scan per poll
START_BLOCK_OFFSET = 100  # how far back from current to start


class PoolMonitor:
    def __init__(self, rpc: RpcClient, chain: Chain, queue: TokenQueue):
        self._rpc = rpc
        self._chain = chain
        self._queue = queue
        self._last_block = 0
        self._seen_pairs: set[str] = set()

    def _get_factories(self) -> list[dict]:
        return FACTORIES.get(self._chain, [])

    def poll(self) -> int:
        factories = self._get_factories()
        if not factories:
            return 0

        try:
            current_block = self._rpc.get_block_number()
        except Exception as exc:
            logger.debug("get_block_number failed for %s: %s", self._chain.name, exc)
            return 0

        if self._last_block == 0:
            self._last_block = max(0, current_block - START_BLOCK_OFFSET)

        from_block = self._last_block + 1
        to_block = min(current_block, from_block + BLOCK_RANGE)

        if from_block >= to_block:
            return 0

        found = 0
        for factory in factories:
            try:
                logs = self._rpc.get_logs(
                    from_block=hex(from_block),
                    to_block=hex(to_block),
                    address=factory["address"],
                    topics=[PAIR_CREATED_TOPIC],
                )
            except Exception as exc:
                logger.debug("get_logs failed for %s factory %s: %s",
                             self._chain.name, factory["address"][:12], exc)
                continue

            if not isinstance(logs, list):
                continue
            for log in logs:
                if not isinstance(log, dict):
                    continue
                pair_addr = log.get("address", "")
                if pair_addr in self._seen_pairs:
                    continue
                self._seen_pairs.add(pair_addr)

                topics = log.get("topics", [])
                if len(topics) < 3:
                    continue
                token0 = "0x" + topics[1][26:] if len(topics[1]) >= 26 else topics[1]
                token1 = "0x" + topics[2][26:] if len(topics[2]) >= 26 else topics[2]

                self._enqueue_token(token0, factory["dex"])
                self._enqueue_token(token1, factory["dex"])
                found += 1

        self._last_block = to_block
        return found

    def _enqueue_token(self, token_address: str, dex: str):
        chain_str = self._chain.name.lower()
        self._queue.add(
            chain=self._chain,
            token_address=token_address,
            pair_address="",
            symbol="",
            liquidity_usd=0,
            dex=dex,
        )

    def run(self):
        logger.info("PoolMonitor started for %s", self._chain.name)
        while True:
            try:
                found = self.poll()
                if found:
                    logger.info("Found %d new pairs on %s", found, self._chain.name)
            except Exception as exc:
                logger.error("PoolMonitor error on %s: %s", self._chain.name, exc)
            time.sleep(POLL_INTERVAL)
