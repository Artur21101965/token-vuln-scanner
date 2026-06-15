from __future__ import annotations

import json
import logging
from decimal import Decimal
from types import SimpleNamespace
from typing import Optional

from src.types import Chain

logger = logging.getLogger(__name__)

DEXSCREENER_WS_URL = "wss://api.dexscreener.com/token-profiles/latest/v1"
SUPPORTED_CHAINS = {"ethereum", "bsc", "solana"}
LIQUIDITY_THRESHOLD_USD = 500


class DexScreenerMonitor:
    def __init__(self, queue, min_liquidity: float = LIQUIDITY_THRESHOLD_USD):
        self._queue = queue
        self._min_liquidity = min_liquidity

    def _filter_by_liquidity(self, token) -> bool:
        return token.liquidity_usd >= self._min_liquidity

    def _parse_pair(self, msg: dict) -> Optional[SimpleNamespace]:
        chain_id = msg.get("chainId", "")
        if chain_id not in SUPPORTED_CHAINS:
            return None

        base = msg.get("baseToken", {})
        token_address = base.get("address", "")
        symbol = base.get("symbol", "")

        if not token_address:
            return None

        t = SimpleNamespace()
        t.chain = chain_id
        t.token_address = token_address
        t.pair_address = msg.get("pairAddress", "")
        t.symbol = symbol
        t.liquidity_usd = float(msg.get("liquidity", {}).get("usd", 0))
        t.dex = msg.get("dexId", "")
        return t

    def _process_message(self, raw: str) -> None:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return

        pairs = data if isinstance(data, list) else [data]
        for pair in pairs:
            token = self._parse_pair(pair)
            if token is None:
                continue
            if not self._filter_by_liquidity(token):
                continue
            self._queue.add(
                chain=Chain.from_str(token.chain),
                token_address=token.token_address,
                pair_address=token.pair_address,
                symbol=token.symbol,
                liquidity_usd=Decimal(str(token.liquidity_usd)),
                dex=token.dex,
            )
            logger.info(
                "New token: %s ($%.0f) on %s — %s",
                token.symbol, token.liquidity_usd, token.chain, token.token_address,
            )

    async def run(self):
        import asyncio

        import websockets

        while True:
            try:
                async with websockets.connect(DEXSCREENER_WS_URL) as ws:
                    logger.info("Connected to DexScreener WebSocket")
                    async for message in ws:
                        self._process_message(message)
            except Exception as exc:
                logger.error("WebSocket error: %s", exc)
                await asyncio.sleep(5)
