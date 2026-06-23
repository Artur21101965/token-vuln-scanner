"""RugCheck API — Solana-specific authority and lock checks."""
import json
import urllib.request
from typing import Optional
import logging

logger = logging.getLogger(__name__)

RUGCHECK_URL = "https://api.rugcheck.xyz/v1/tokens/{}/report/summary"


def enrich_rugcheck(token_address: str) -> Optional[dict]:
    """RugCheck report for Solana token."""
    try:
        url = RUGCHECK_URL.format(token_address)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        # RugCheck returns different scores and flags
        score = data.get("score", 0)
        risks = data.get("risks", [])
        risk_names = [r.get("name", "") for r in risks]

        # Check for revoked authorities
        authorities_revoked = "Freeze Authority still enabled" not in " ".join(risk_names)
        mint_revoked = "Mint Authority still enabled" not in " ".join(risk_names)

        # Check LP lock
        lp_locked = "Liquidity is not locked" not in " ".join(risk_names)

        # Check for rug history
        is_rug = "Previously rugged" in " ".join(risk_names)

        return {
            "source": "rugcheck",
            "score": score,
            "authorities_revoked": authorities_revoked and mint_revoked,
            "lp_locked": lp_locked,
            "is_rug": is_rug,
            "total_risks": len(risks),
            "risk_names": risk_names[:5],
            "top_holder_pct": float(data.get("topHolders", [{}])[0].get("pct", 0) or 0) if data.get("topHolders") else 0,
        }
    except Exception as e:
        logger.debug("RugCheck error for %s: %s", token_address[:12], e)
        return None
