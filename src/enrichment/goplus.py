"""GoPlus Security API — honeypot, dangerous rights, tax checks for EVM + Solana."""
import json
import urllib.request
from typing import Optional
import logging

logger = logging.getLogger(__name__)

GOPLUS_EVM_URL = "https://api.gopluslabs.io/api/v1/token_security/{}?contract_addresses={}"
GOPLUS_SOLANA_URL = "https://api.gopluslabs.io/api/v1/solana/token_security/{}?contract_addresses={}"

CHAIN_IDS = {
    "ethereum": 1, "polygon": 137, "bsc": 56, "arbitrum": 42161,
    "base": 8453, "optimism": 10, "avalanche": 43114,
}


def enrich_goplus_evm(token_address: str, chain: str) -> Optional[dict]:
    """GoPlus security check for EVM chains."""
    chain_id = CHAIN_IDS.get(chain, 1)
    try:
        url = GOPLUS_EVM_URL.format(chain_id, token_address)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        result = data.get("result", {})
        token_data = result.get(token_address.lower(), {})
        if not token_data:
            return None

        is_honeypot = token_data.get("is_honeypot", "0")
        if isinstance(is_honeypot, str):
            is_honeypot = int(is_honeypot)

        buy_tax = float(token_data.get("buy_tax", "0") or 0)
        sell_tax = float(token_data.get("sell_tax", "0") or 0)
        holder_top_pct = float(token_data.get("holders", [{}])[0].get("percent", "0") or 0) if token_data.get("holders") else 0

        return {
            "source": "goplus",
            "is_honeypot": bool(is_honeypot),
            "sell_tax_pct": min(sell_tax, 100),
            "buy_tax_pct": min(buy_tax, 100),
            "holder_top_pct": holder_top_pct,
            "is_proxy": token_data.get("is_proxy", "0") == "1",
            "is_open_source": token_data.get("is_open_source", "0") == "1",
            "owner_address": token_data.get("owner_address", ""),
            "owner_balance": token_data.get("owner_balance", "0"),
            "creator_address": token_data.get("creator_address", ""),
            "token_name": token_data.get("token_name", ""),
            "token_symbol": token_data.get("token_symbol", ""),
            "dangerous_rights": bool(is_honeypot) or sell_tax > 80 or holder_top_pct > 50,
        }
    except Exception as e:
        logger.debug("GoPlus EVM error for %s: %s", token_address[:12], e)
        return None


def enrich_goplus_solana(token_address: str) -> Optional[dict]:
    """GoPlus security check for Solana tokens."""
    try:
        url = GOPLUS_SOLANA_URL.format(1, token_address)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        result = data.get("result", {})
        token_data = result.get(token_address, {})
        if not token_data:
            return None

        is_mintable = token_data.get("is_mintable", 0)
        if isinstance(is_mintable, str):
            is_mintable = int(is_mintable)

        is_freezable = token_data.get("is_freezable", 0)
        if isinstance(is_freezable, str):
            is_freezable = int(is_freezable)

        return {
            "source": "goplus",
            "is_mintable": bool(is_mintable),
            "is_freezable": bool(is_freezable),
            "current_supply": token_data.get("current_supply", "0"),
            "creator_address": token_data.get("creator_address", ""),
            "owner_address": token_data.get("owner_address", ""),
            "dangerous_rights": bool(is_mintable) or bool(is_freezable),
        }
    except Exception as e:
        logger.debug("GoPlus Solana error for %s: %s", token_address[:12], e)
        return None
