import httpx
import json
import logging
import random
from decimal import Decimal
from typing import Optional
from src.db.queue import TokenQueue
from src.types import Chain

logger = logging.getLogger(__name__)

BOOSTS_API = "https://api.dexscreener.com/token-boosts/latest/v1"
TOKEN_API = "https://api.dexscreener.com/latest/dex/tokens/{address}"
SEARCH_TERMS = ["a", "b", "c", "d", "e", "t", "s", "m", "p", "x", "doge", "pepe", "moon", "safe"]
SUPPORTED_CHAINS = {"ethereum", "bsc", "arbitrum", "base", "polygon", "avalanche", "optimism", "zksync", "linea", "scroll", "solana"}
EVM_CHAINS = [c for c in SUPPORTED_CHAINS if c != "solana"]


class TopTokenScanner:
    def __init__(self, queue: TokenQueue, min_liquidity: float = 500):
        self._queue = queue
        self._min_liquidity = Decimal(str(min_liquidity))
        self._seen: set[str] = set()

    def _enrich_token(self, http: httpx.Client, chain_id: str, token_address: str) -> Optional[tuple]:
        try:
            resp = http.get(TOKEN_API.format(address=token_address), timeout=10)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return None

        pairs = data.get("pairs") or []
        for pair in pairs:
            if pair.get("chainId") != chain_id:
                continue
            liquidity = float((pair.get("liquidity") or {}).get("usd", 0) or 0)
            if liquidity < float(self._min_liquidity):
                continue
            return (
                token_address,
                pair.get("pairAddress", ""),
                (pair.get("baseToken") or {}).get("symbol", ""),
                liquidity,
                pair.get("dexId", ""),
            )
        return None

    def scan(self) -> int:
        http = httpx.Client(timeout=15)
        try:
            resp = http.get(BOOSTS_API, timeout=15)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.debug("Boost API error: %s", exc)
            return 0

        items = data.get("data") or data if isinstance(data, list) else []
        if isinstance(items, dict):
            items = [items]

        enqueued = 0
        for item in items:
            chain_id = (item.get("chainId") or "").lower()
            if chain_id not in SUPPORTED_CHAINS:
                continue
            token_address = item.get("tokenAddress") or item.get("address") or ""
            if not token_address:
                continue
            key = f"{chain_id}:{token_address}"
            if key in self._seen:
                continue
            self._seen.add(key)

            result = self._enrich_token(http, chain_id, token_address)
            if result is None:
                continue

            addr, pair, symbol, liquidity, dex = result
            self._queue.add(
                chain=Chain.from_str(chain_id),
                token_address=addr,
                pair_address=pair,
                symbol=symbol,
                liquidity_usd=Decimal(str(liquidity)),
                dex=dex,
            )
            enqueued += 1
            logger.info("Boost token queued: %s ($%.0f) on %s", symbol, liquidity, chain_id)

        return enqueued

    def scan_bulk(self, max_per_chain: int = 20) -> int:
        """Scan DexScreener search + profiles for EVM tokens, enqueue."""
        http = httpx.Client(timeout=15)
        enqueued = 0
        seen_this_pass: set[str] = set()

        # 1. Token profiles (newly created)
        try:
            resp = http.get("https://api.dexscreener.com/token-profiles/latest/v1", timeout=15)
            profiles = resp.json()
            if isinstance(profiles, list):
                for p in profiles:
                    chain_id = (p.get("chainId") or "").lower()
                    if chain_id not in EVM_CHAINS:
                        continue
                    addr = p.get("tokenAddress", "")
                    if addr:
                        seen_this_pass.add(f"{chain_id}:{addr}")
        except Exception:
            pass

        # 2. Search each EVM chain for common terms
        for chain_id in EVM_CHAINS:
            found = 0
            terms = random.sample(SEARCH_TERMS, min(3, len(SEARCH_TERMS)))
            for term in terms:
                if found >= max_per_chain:
                    break
                try:
                    resp = http.get(
                        f"https://api.dexscreener.com/latest/dex/search?q={term}&chain={chain_id}",
                        timeout=10,
                    )
                    pairs = resp.json().get("pairs", [])
                except Exception:
                    continue
                for pair in pairs:
                    if pair.get("chainId") != chain_id:
                        continue
                    bt = pair.get("baseToken", {})
                    addr = bt.get("address", "")
                    if not addr:
                        continue
                    key = f"{chain_id}:{addr}"
                    if key in self._seen or key in seen_this_pass:
                        continue
                    seen_this_pass.add(key)
                    liq = float((pair.get("liquidity") or {}).get("usd", 0) or 0)
                    if liq < float(self._min_liquidity):
                        continue
                    self._queue.add(
                        chain=Chain.from_str(chain_id),
                        token_address=addr,
                        pair_address=pair.get("pairAddress", ""),
                        symbol=bt.get("symbol", ""),
                        liquidity_usd=Decimal(str(liq)),
                        dex=pair.get("dexId", ""),
                    )
                    enqueued += 1
                    found += 1

        # Mark seen from this pass into persistent set
        for key in seen_this_pass:
            self._seen.add(key)

        if enqueued:
            logger.info("Bulk scan enqueued %d EVM tokens", enqueued)
        return enqueued

    def scan_retro(self, max_per_chain: int = 200) -> int:
        """Deep scan: find high-liquidity tokens across all chains using targeted searches."""
        return self.scan_retro_bulk(chains=list(Chain), max_per_chain=max_per_chain)

    def scan_retro_bulk(self, chains: Optional[list[Chain]] = None, max_per_chain: int = 500) -> int:
        """Bulk retro scan — find up to max_per_chain tokens per chain via multi-term DEX Screener search."""
        http = httpx.Client(timeout=15)
        enqueued = 0
        seen_this_pass: set[str] = set()

        retro_terms = [
            "USDC", "USDT", "WETH", "WBTC", "DAI", "token", "coin", "meme",
            "defi", "swap", "farm", "yield", "airdrop", "stake", "bridge",
            "nft", "game", "test", "dapp", "0x", "dexscreener",
        ]
        DEX_CHAIN_MAP = {
            Chain.ETHEREUM: "ethereum", Chain.BSC: "bsc", Chain.ARBITRUM: "arbitrum",
            Chain.BASE: "base", Chain.POLYGON: "polygon", Chain.AVALANCHE: "avalanche",
            Chain.OPTIMISM: "optimism", Chain.ZKSYNC: "zksync", Chain.LINEA: "linea",
            Chain.SCROLL: "scroll", Chain.SOLANA: "solana",
        }
        target_chains = chains or list(DEX_CHAIN_MAP.keys())

        for chain in target_chains:
            dex_chain = DEX_CHAIN_MAP.get(chain)
            if not dex_chain:
                continue
            found = 0
            for term in retro_terms:
                if found >= max_per_chain:
                    break
                try:
                    resp = http.get(
                        f"https://api.dexscreener.com/latest/dex/search?q={term}&chain={dex_chain}",
                        timeout=10,
                    )
                    pairs = resp.json().get("pairs", [])
                except Exception:
                    continue
                for pair in pairs:
                    if pair.get("chainId") != dex_chain:
                        continue
                    bt = pair.get("baseToken", {})
                    addr = bt.get("address", "")
                    if not addr:
                        continue
                    key = f"{dex_chain}:{addr}"
                    if key in self._seen or key in seen_this_pass:
                        continue
                    seen_this_pass.add(key)
                    liq = float((pair.get("liquidity") or {}).get("usd", 0) or 0)
                    if liq < float(self._min_liquidity):
                        continue
                    self._queue.add(
                        chain=chain,
                        token_address=addr,
                        pair_address=pair.get("pairAddress", ""),
                        symbol=bt.get("symbol", ""),
                        liquidity_usd=Decimal(str(liq)),
                        dex=pair.get("dexId", ""),
                    )
                    enqueued += 1
                    found += 1

        for key in seen_this_pass:
            self._seen.add(key)

        if enqueued:
            logger.info("Retro bulk scan enqueued %d tokens across %d chains", enqueued, len(target_chains))
        return enqueued
