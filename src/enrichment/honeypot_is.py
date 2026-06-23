"""Honeypot.is API — EVM-specific honeypot detection."""
import json
import urllib.request
from typing import Optional
import logging

logger = logging.getLogger(__name__)

HONEYPOT_URL = "https://api.honeypot.is/v2/IsHoneypot?address={}&chainID={}"

CHAIN_IDS = {
    "ethereum": 1, "base": 8453, "arbitrum": 42161,
    "polygon": 137, "bsc": 56, "optimism": 10, "avalanche": 43114,
}


def enrich_honeypot(token_address: str, chain: str) -> Optional[dict]:
    """Honeypot.is API check (EVM only)."""
    chain_id = CHAIN_IDS.get(chain)
    if not chain_id:
        return None

    try:
        url = HONEYPOT_URL.format(token_address, chain_id)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        is_honeypot = data.get("isHoneypot", False)
        if isinstance(is_honeypot, str):
            is_honeypot = is_honeypot.lower() == "true"

        return {
            "source": "honeypot_is",
            "is_honeypot": is_honeypot,
            "simulation_success": data.get("simulationSuccess", False),
            "buy_tax_pct": float(data.get("buyTax", 0) or 0),
            "sell_tax_pct": float(data.get("sellTax", 0) or 0),
            "pair_address": data.get("pairAddress", ""),
        }
    except Exception as e:
        logger.debug("Honeypot.is error for %s: %s", token_address[:12], e)
        return None
