"""DexScreener API — enrichment data for any token on any chain."""
import json
import urllib.request
from typing import Optional
import logging

logger = logging.getLogger(__name__)

DEXSCREENER_URL = "https://api.dexscreener.com/latest/dex/tokens/{}"


def enrich_dexscreener(token_address: str) -> Optional[dict]:
    """Fetch token data from DexScreener. Returns dict with price, liquidity, volume, holders."""
    try:
        url = DEXSCREENER_URL.format(token_address)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        pairs = data.get("pairs", [])
        if not pairs:
            return None

        # Find the pair with highest liquidity (usually the main one)
        best = max(pairs, key=lambda p: float(p.get("liquidity", {}).get("usd", 0) or 0))

        result = {
            "price_usd": float(best.get("priceUsd", 0) or 0),
            "liquidity_usd": float(best.get("liquidity", {}).get("usd", 0) or 0),
            "fdv_usd": float(best.get("fdv", 0) or 0),
            "volume_5m": float(best.get("volume", {}).get("m5", 0) or 0),
            "volume_1h": float(best.get("volume", {}).get("h1", 0) or 0),
            "volume_24h": float(best.get("volume", {}).get("h24", 0) or 0),
            "price_change_5m": float(best.get("priceChange", {}).get("m5", 0) or 0),
            "price_change_1h": float(best.get("priceChange", {}).get("h1", 0) or 0),
            "txns_5m_buys": int(best.get("txns", {}).get("m5", {}).get("buys", 0) or 0),
            "txns_5m_sells": int(best.get("txns", {}).get("m5", {}).get("sells", 0) or 0),
            "txns_1h_buys": int(best.get("txns", {}).get("h1", {}).get("buys", 0) or 0),
            "txns_1h_sells": int(best.get("txns", {}).get("h1", {}).get("sells", 0) or 0),
            "pair_address": best.get("pairAddress", ""),
            "base_token": best.get("baseToken", {}).get("symbol", "?"),
            "dex": best.get("dexId", "unknown"),
            "chain": best.get("chainId", "unknown"),
            "url": best.get("url", ""),
            "pair_created_at": best.get("pairCreatedAt", 0),
            "raw_pairs_count": len(pairs),
        }
        return result
    except Exception as e:
        logger.debug("DexScreener error for %s: %s", token_address[:12], e)
        return None
