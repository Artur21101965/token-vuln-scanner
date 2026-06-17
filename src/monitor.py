from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from decimal import Decimal
from typing import Optional

import httpx
import websockets

from src.types import Chain

logger = logging.getLogger(__name__)

DEXSCREENER_WS_URL = "wss://api.dexscreener.com/token-profiles/latest/v1"
DEXSCREENER_TOKEN_API = "https://api.dexscreener.com/latest/dex/tokens/{address}"
SUPPORTED_CHAINS = {"ethereum", "bsc", "arbitrum", "base", "polygon", "avalanche", "optimism", "zksync", "linea", "scroll", "solana"}
LIQUIDITY_THRESHOLD_USD = 0
MAX_CONCURRENT_FETCHES = 10


@dataclass
class _ParsedPair:
    chain: str
    token_address: str
    pair_address: str
    symbol: str
    liquidity_usd: float
    dex: str


class DexScreenerMonitor:
    def __init__(self, queue, min_liquidity: float = LIQUIDITY_THRESHOLD_USD):
        self._queue = queue
        self._min_liquidity = min_liquidity
        self._seen: set[str] = set()
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)

    def _filter_by_liquidity(self, token) -> bool:
        return Decimal(str(token.liquidity_usd)) >= self._min_liquidity

    def _parse_pair(self, msg: dict) -> Optional[_ParsedPair]:
        chain_id = msg.get("chainId", "")
        if chain_id not in SUPPORTED_CHAINS:
            return None

        base = msg.get("baseToken", {})
        token_address = base.get("address", "")
        symbol = base.get("symbol", "")

        if not token_address:
            return None

        liquidity_usd = msg.get("liquidity", {}) or {}
        return _ParsedPair(
            chain=chain_id,
            token_address=token_address,
            pair_address=msg.get("pairAddress", ""),
            symbol=symbol,
            liquidity_usd=float(liquidity_usd.get("usd", 0) or 0),
            dex=msg.get("dexId", ""),
        )

    async def _enrich_and_enqueue(self, chain_id: str, token_address: str, client: httpx.AsyncClient) -> None:
        key = f"{chain_id}:{token_address}"
        if key in self._seen:
            return
        self._seen.add(key)

        async with self._semaphore:
            try:
                resp = await client.get(
                    DEXSCREENER_TOKEN_API.format(address=token_address),
                    timeout=10,
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                logger.debug("Failed to fetch pairs for %s: %s", token_address, exc)
                return

        self._enqueue_from_pairs(chain_id, data.get("pairs") or [])

    def _enqueue_from_pairs(self, chain_id: str, pairs: list[dict]) -> None:
        for pair in pairs:
            if pair.get("chainId") != chain_id:
                continue
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
                "New token: %s ($%.0f) on %s — %s (pair: %s)",
                token.symbol, token.liquidity_usd, token.chain,
                token.token_address, token.pair_address,
            )
            break  # one pair per token is enough

    async def _process_message(self, raw: str, client: httpx.AsyncClient) -> None:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("Malformed JSON received: %s", raw)
            return

        items = data if isinstance(data, list) else data.get("data", data if isinstance(data, dict) else [])
        if isinstance(items, dict):
            items = [items]
        if not isinstance(items, list):
            return

        tasks = []
        for item in items:
            chain_id = item.get("chainId", "")
            if chain_id not in SUPPORTED_CHAINS:
                continue
            token_address = item.get("tokenAddress", "") or item.get("token_address", "")
            if not token_address:
                token_address = (item.get("baseToken") or {}).get("address", "")
            if token_address:
                tasks.append(self._enrich_and_enqueue(chain_id, token_address, client))

        if tasks:
            await asyncio.gather(*tasks)

    async def run(self):
        delay = 1
        async with httpx.AsyncClient() as client:
            while True:
                try:
                    async with websockets.connect(DEXSCREENER_WS_URL) as ws:
                        logger.info("Connected to DexScreener WebSocket")
                        delay = 1
                        async for message in ws:
                            await self._process_message(message, client)
                except Exception as exc:
                    logger.error("WebSocket error: %s", exc)
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, 60)
