"""
ANTI-SCAM INTEGRATOR — runs all enrichment sources in parallel, merges results.

For each token:
  1. DexScreener → liquidity, volume, holders
  2. GoPlus → honeypot, dangerous rights, tax
  3. RugCheck (Solana) → authority revoked, LP locked
  4. Honeypot.is (EVM) → honeypot simulation

Returns: AntiScamResult with pass/fail + all check details.
"""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from src.enrichment.dexscreener import enrich_dexscreener
from src.enrichment.goplus import enrich_goplus_evm, enrich_goplus_solana
from src.enrichment.rugcheck import enrich_rugcheck
from src.enrichment.honeypot_is import enrich_honeypot

logger = logging.getLogger(__name__)


class AntiScamResult:
    def __init__(self):
        self.passed = True
        self.checks: list[dict] = []
        self.dexscreener: Optional[dict] = None
        self.goplus: Optional[dict] = None
        self.rugcheck: Optional[dict] = None
        self.honeypot: Optional[dict] = None
        self.critical_failures: list[str] = []
        self.warnings: list[str] = []

    def add_check(self, code: str, name: str, passed: bool, critical: bool, source: str, details: str = ""):
        self.checks.append({
            "code": code, "name": name, "passed": passed,
            "critical": critical, "source": source, "details": details,
        })
        if not passed and critical:
            self.passed = False
            self.critical_failures.append(f"{code}: {name} [{source}]")
        elif not passed:
            self.warnings.append(f"{code}: {name} [{source}]")


def scan_token(token_address: str, chain: str, is_solana: bool = False) -> AntiScamResult:
    """Run all enrichment sources in parallel for a single token."""
    result = AntiScamResult()

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {}

        # DexScreener (all chains)
        futures["dexscreener"] = pool.submit(enrich_dexscreener, token_address)

        if is_solana:
            futures["goplus"] = pool.submit(enrich_goplus_solana, token_address)
            futures["rugcheck"] = pool.submit(enrich_rugcheck, token_address)
            futures["honeypot"] = pool.submit(lambda: None)  # Honeypot.is is EVM only
        else:
            futures["goplus"] = pool.submit(enrich_goplus_evm, token_address, chain)
            futures["rugcheck"] = pool.submit(lambda: None)  # RugCheck is Solana only
            futures["honeypot"] = pool.submit(enrich_honeypot, token_address, chain)

        # Collect results
        for source, future in futures.items():
            try:
                data = future.result(timeout=15)
                setattr(result, source, data)
            except Exception as e:
                logger.debug("%s failed: %s", source, e)

    # ---- Evaluate checks ----

    # S1: Honeypot detection
    independent_scanners = 0
    if result.honeypot:
        is_hp = result.honeypot.get("is_honeypot", False)
        result.add_check("S1", "honeypot", not is_hp, True, "honeypot.is",
                         f"honeypot={is_hp}")
        independent_scanners += 1

    if result.goplus:
        goplus_hp = result.goplus.get("is_honeypot", False) if "is_honeypot" in result.goplus else (
            result.goplus.get("dangerous_rights", False))
        result.add_check("S1", "honeypot", not goplus_hp, True, "goplus",
                         f"dangerous={goplus_hp}")
        independent_scanners += 1

    # S0: Minimum independent scanners
    if independent_scanners < 2 and not is_solana:
        result.passed = False
        result.critical_failures.append("S0: <2 independent scanners")

    # S2: Sell tax
    sell_tax = 0
    if result.honeypot:
        sell_tax = max(sell_tax, result.honeypot.get("sell_tax_pct", 0))
    if result.goplus and "sell_tax_pct" in result.goplus:
        sell_tax = max(sell_tax, result.goplus.get("sell_tax_pct", 0))
    result.add_check("S2", "sell_tax", sell_tax <= 10, False, "combined",
                     f"tax={sell_tax:.1f}%")

    # S3: Dangerous owner rights
    if result.goplus:
        dangerous = result.goplus.get("dangerous_rights", False)
        result.add_check("S3", "dangerous_rights", not dangerous, True, "goplus",
                         f"dangerous={dangerous}")

    # S4: Proxy / unverified
    if result.goplus and "is_proxy" in result.goplus:
        is_proxy = result.goplus.get("is_proxy", False)
        is_open = result.goplus.get("is_open_source", False)
        result.add_check("S4", "proxy_unverified", not (is_proxy and not is_open), False, "goplus",
                         f"proxy={is_proxy} open_source={is_open}")

    # S5: LP lock (Solana only)
    if result.rugcheck:
        lp_locked = result.rugcheck.get("lp_locked", False)
        result.add_check("S5", "lp_locked", lp_locked, False, "rugcheck",
                         f"locked={lp_locked}")

    # S6: Top holder concentration
    if result.dexscreener:
        top_pct = result.dexscreener.get("holder_top_pct", 0) or result.goplus.get("holder_top_pct", 0) if result.goplus else 0
        result.add_check("S6", "holder_concentration", top_pct < 30, False, "dexscreener",
                         f"top_holder={top_pct:.1f}%")

    # S7: Authorities revoked (Solana only)
    if result.rugcheck:
        revoked = result.rugcheck.get("authorities_revoked", False)
        result.add_check("S7", "authorities_revoked", revoked, True, "rugcheck",
                         f"revoked={revoked}")

    # S8: Deployer rug history
    if result.rugcheck:
        is_rug = result.rugcheck.get("is_rug", False)
        result.add_check("S8", "deployer_rug_history", not is_rug, False, "rugcheck",
                         f"rug={is_rug}")

    return result


def quick_drainable_check(token_address: str, chain: str) -> bool:
    """Fast check: is this token likely exploitable for drain? Returns True if worth deeper scan."""
    result = scan_token(token_address, chain, is_solana=(chain == "solana"))

    # For drain: we want tokens with dangerous rights OR authorities not revoked
    # These are tokens where someone (maybe us) could do something malicious

    if result.critical_failures:
        # Token has security issues → worth scanning for exploit
        return True

    if result.rugcheck and not result.rugcheck.get("authorities_revoked", False):
        # Solana: mint/freeze authority active
        return True

    if result.goplus and result.goplus.get("dangerous_rights", False):
        # EVM: owner has dangerous rights
        return True

    return False
