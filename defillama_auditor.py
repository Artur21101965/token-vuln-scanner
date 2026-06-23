"""
DEFILLAMA PROTOCOL AUDITOR — autonomous daily audit of top protocols.

Every 6 hours:
  1. Fetch top 50 protocols ($1M-$100M TVL) from DefiLlama
  2. Get contract addresses + implementation addresses
  3. Fetch source code via Explorer V2
  4. Deep audit for vulnerabilities
  5. Send Telegram alert for findings

Usage: python defillama_auditor.py
"""
import os
import json
import time
import logging
import urllib.request
from typing import Optional

from src.rpc import RpcClient
from src.explorer import ExplorerClient
from src.types import Chain
from src.signer import load_evm_private_key
from src.utils import send_alert

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DL-AUDIT] %(message)s")
logger = logging.getLogger("dl-audit")
logger.setLevel(logging.INFO)

DEFILLAMA_API = "https://api.llama.fi"
EXPLORER_KEY = os.environ.get("ETHERSCAN_KEY", "")

RPC_URLS = {
    "ethereum": "https://mainnet.infura.io/v3/ce8484bca20b4ce69df068e087aff6a5",
    "base": "https://mainnet.base.org",
    "arbitrum": "https://arbitrum-mainnet.infura.io/v3/fe313507591449e883740a9bd602a9fe",
    "polygon": "https://polygon-mainnet.infura.io/v3/fe313507591449e883740a9bd602a9fe",
}

CHAIN_TO_ENUM = {
    "ethereum": Chain.ETHEREUM,
    "base": Chain.BASE,
    "arbitrum": Chain.ARBITRUM,
    "polygon": Chain.POLYGON,
    "bsc": Chain.BSC,
    "optimism": Chain.OPTIMISM,
    "avalanche": Chain.AVALANCHE,
}
# Chains we have Explorer V2 access to (all use same Etherscan key)
SCANNABLE_CHAINS = {"ethereum", "base", "arbitrum", "polygon", "bsc", "optimism", "avalanche"}

# EIP-1967 implementation storage slot
IMPL_SLOT = int("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)


def fetch_protocols() -> list[dict]:
    """Get top 50 medium protocols from DefiLlama."""
    req = urllib.request.Request(f"{DEFILLAMA_API}/protocols", headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        protocols = json.loads(r.read())

    medium = [p for p in protocols if p.get("tvl") and 1_000_000 < p["tvl"] < 100_000_000]
    medium.sort(key=lambda p: -p["tvl"])
    return medium[:50]


def get_protocol_details(slug: str) -> Optional[dict]:
    """Get protocol details including contract addresses."""
    try:
        req = urllib.request.Request(f"{DEFILLAMA_API}/protocol/{slug}", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        return data
    except Exception:
        return None


def extract_address(detail: dict) -> list[tuple[str, str]]:
    """Extract contract addresses from protocol detail."""
    addrs = []
    for key, val in detail.items():
        if isinstance(val, str):
            v = val.strip()
            # Format: "chain:0x..."
            if ":" in v and "0x" in v:
                parts = v.split(":")
                if len(parts) == 2 and parts[1].startswith("0x") and len(parts[1]) == 42:
                    addrs.append((parts[0].lower(), parts[1]))
            elif v.startswith("0x") and len(v) == 42:
                addrs.append(("ethereum", v))
    return addrs


def get_implementation(rpc: RpcClient, proxy_addr: str) -> Optional[str]:
    """Get EIP-1967 implementation address from proxy."""
    try:
        raw = rpc.get_storage_at(proxy_addr, IMPL_SLOT)
        impl = "0x" + raw[-40:]
        if impl and int(impl, 16) != 0:
            return impl
    except Exception:
        pass
    return None


def audit_source(src: str, name: str) -> list[str]:
    """Deep audit single contract source code."""
    issues = []
    src_l = src.lower()

    if "selfdestruct" in src_l and "onlyowner" not in src_l:
        issues.append("🚨 SELFDESTRUCT без onlyOwner")
    if "delegatecall" in src_l and "msg.data" not in src_l:
        pass  # proxy
    if ".call{" in src_l and "success" not in src_l:
        issues.append("⚠️ call без проверки успеха")
    if "tx.origin" in src_l:
        issues.append("⚠️ tx.origin для авторизации")

    # Custom checks for lending protocols
    if any(k in name.lower() for k in ["lend", "borrow", "loan"]):
        if "function liquidate" in src_l and "onlyowner" not in src_l:
            issues.append("⚠️ liquidate() без проверки")

    return issues


def run_audit_cycle():
    """One complete audit cycle."""
    protocols = fetch_protocols()
    findings = []
    audited = 0

    for proto in protocols:
        detail = get_protocol_details(proto["slug"])
        if not detail:
            continue

        addrs = extract_address(detail)
        name = detail.get("name", proto.get("name", "?"))

        for chain_key, addr in addrs:
            chain_key = chain_key.lower()
            if chain_key not in SCANNABLE_CHAINS or chain_key not in CHAIN_TO_ENUM:
                continue

            chain_enum = CHAIN_TO_ENUM[chain_key]

            try:
                explorer = ExplorerClient(EXPLORER_KEY)

                # Get source code directly via Explorer V2 (no RPC needed)
                src = explorer.get_source_code(addr, chain_enum)
                if not src or len(src) < 100:
                    continue

                audited += 1
                issues = audit_source(src, name)
                if issues:
                    logger.warning("%s (%s): %d issues", name, chain_key, len(issues))
                    for iss in issues:
                        logger.warning("  %s", iss)
                    findings.append((name, chain_key, target, issues))

            except Exception:
                continue
            time.sleep(0.5)

        if audited >= 30:
            break

    logger.info("Cycle done: audited=%d findings=%d", audited, len(findings))

    if findings:
        with open("defillama_findings.txt", "a") as f:
            f.write(f"\n--- {time.ctime()} ---\n")
            for name, chain, addr, issues in findings:
                f.write(f"{name} | {chain} | {addr}\n")
                for iss in issues:
                    f.write(f"  {iss}\n")
        send_alert(f"DefiLlama аудит: {len(findings)} протоколов с проблемами", "INFO")

    return findings


def main():
    logger.info("=" * 50)
    logger.info("DEFILLAMA PROTOCOL AUDITOR — starting")
    logger.info("=" * 50)

    cycle = 1
    while True:
        logger.info("Cycle #%d", cycle)
        run_audit_cycle()
        logger.info("Sleeping 6 hours...")
        time.sleep(21600)
        cycle += 1


if __name__ == "__main__":
    main()
