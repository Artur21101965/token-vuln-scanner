"""
DEEP HUNTER — targeted scan of high-value targets on under-audited chains.

Targets:
  1. BSC — PancakeSwap forks, unaudited tokens
  2. Cross-chain bridges — Ronin, Wormhole, LayerZero, Hop, Across
  3. MEV searcher contracts — bytecode + source deep analysis  
  4. Linea/Scroll — new L2s, less audited code

Usage: python deep_hunter.py [chain|all]
"""
import os, tomllib, logging, time, json, urllib.request
from typing import Optional
from eth_utils import keccak

from src.rpc import RpcClient
from src.explorer import ExplorerClient
from src.types import Chain
from src.signer import load_evm_private_key
from src.evmole_utils import get_functions

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DEEP] %(message)s")
logger = logging.getLogger("deep-hunter")

# ============================================================
# CROSS-CHAIN BRIDGES — the biggest prizes
# ============================================================

BRIDGES = {
    "ethereum": [
        ("0x8315177aB297bA92A06054cE80a67Ed4DBd7ed3a", "Arbitrum Bridge"),
        ("0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1", "Polygon Bridge ETH"),
        ("0x3154Cf16ccdb4C6d922629664174b904d80F2C35", "Base Bridge"),
        ("0x49048044D57e1C92A77f79988d21Fa8fAF74E97e", "Optimism Bridge"),
        ("0x3ee18B2214AFF97000D974cf647E7C347E8fa585", "Wormhole"),
        ("0x5a3e6A77ba2f983eC0d371eA3B475F8Bc0811AD5", "LayerZero"),
        ("0xb8901acB165ed027E32754E0FFe830802919727f", "Hop Protocol"),
        ("0x3666f603Cc164936C1b87e207F36BEBa4AC5f18a", "Across Protocol"),
        ("0x1D4f657C235AcEb8F5fBcb83CA134Badb5B86d3A", "Synapse Bridge"),
        ("0x173272739Bd7AaA673a9f5B4D58638AB6fEdc1C4", "Multichain (dead)"),
    ],
    "polygon": [
        ("0xA0c68C638235ee32657e8f720a23ceC1bFc77C77", "Polygon Bridge ETH"),
        ("0x8484Ef722627bf18ca5Ae6BcF031c23E6e922B30", "Polygon Bridge Token"),
    ],
    "arbitrum": [
        ("0x8315177aB297bA92A06054cE80a67Ed4DBd7ed3a", "Arbitrum Bridge L1"),
    ],
    "base": [
        ("0x3154Cf16ccdb4C6d922629664174b904d80F2C35", "Base Bridge"),
        ("0x4200000000000000000000000000000000000010", "Base L2ToL1Bridge"),
    ],
}

# ============================================================
# MEV SEARCHER CONTRACTS
# ============================================================

MEV_CONTRACTS = [
    "0x0000000000007F150Bd6f54c40A34d7C3d5e9f56",  # jaredfromsubway
    "0x6B75d8AF000000e20B7a7DDf000Ba900b4009A80",  # beaverbuild
    "0xA57B8a5584442B467b4689F1144D269d096A3daF",  # rsync
    "0x1f2F10D1C40777AE1Da742455c65828FF36Df387",  # manifold
    "0xae2Fc483527B8EF99EB5D9B44875F005ba1FaE13",  # jared v2
    "0x43a5A7bfa5A94728C0b0D4bA35dA287AF05fceC3",  # banana
    "0x07e828A4d4FfDAF8e3E2C7D39cb12A8eEfb54448",  # c0ffeebabe
]

# ============================================================
# DEEP ANALYSIS FUNCTIONS
# ============================================================

def deep_scan_contract(rpc: RpcClient, explorer: ExplorerClient, addr: str, chain: Chain, name: str) -> list[str]:
    """Ultra-deep analysis of a single contract."""
    issues = []

    try:
        code = rpc.eth_get_code(addr)
        bal = int(str(rpc.call("eth_getBalance", [addr, "latest"])), 16) / 1e18
    except Exception:
        return []

    if not code or len(code) <= 4:
        return []

    code_str = str(code).lower().replace("0x", "")
    functions = get_functions(code)

    # === Bytecode-level ===
    # Bridge-specific: message passing functions
    if "f4" in code_str and "35" in code_str:  # DELEGATECALL + CALLDATALOAD
        issues.append("⚠️ delegatecall with calldata — proxy takeover possible")

    # MEV-specific: unprotected contract deployment
    if "f0" in code_str:  # CREATE opcode
        if "f5" in code_str:  # CREATE2 nearby
            issues.append("ℹ️ Creates new contracts (MEV bot infrastructure)")

    # Admin functions
    admin_selectors = {
        "f2fde38b": "transferOwnership",
        "13af4035": "setOwner",
        "715018a6": "renounceOwnership",
        "8456cb59": "pause",
        "3f4ba83a": "unpause",
    }
    signer = load_evm_private_key()
    for sel, name_sel in admin_selectors.items():
        if sel in code_str:
            try:
                gas = rpc.eth_call(addr, "0x" + sel, from_address=signer.address)
                if gas and gas != "0x":
                    issues.append(f"🚨 {name_sel}() CALLABLE — unprotected admin function!")
            except Exception:
                pass

    # === Source code level ===
    try:
        src = explorer.get_source_code(addr, chain)
        if src and len(src) > 100:
            src_lower = src.lower()
            if "selfdestruct" in src_lower and "onlyowner" not in src_lower:
                issues.append("🚨 SELFDESTRUCT without onlyOwner!")
            if "delegatecall" in src_lower and "msg.sender" not in src_lower:
                issues.append("⚠️ delegatecall without sender check")
            if "tx.origin" in src_lower:
                issues.append("⚠️ Uses tx.origin for auth (phishing risk)")
            if ".call{" in src_lower and "success" not in src_lower.split(".call{")[1][:50]:
                issues.append("⚠️ Low-level call without success check")
    except Exception:
        pass

    return issues


def scan_chain(chain_key: str, rpc_url: str):
    """Deep scan all targets on one chain."""
    rpc = RpcClient(rpc_url, max_retries=2)
    explorer = ExplorerClient(os.environ.get("ETHERSCAN_KEY", ""))

    if chain_key == "ethereum":
        chain_enum = Chain.ETHEREUM
    elif chain_key == "polygon":
        chain_enum = Chain.POLYGON
    elif chain_key == "arbitrum":
        chain_enum = Chain.ARBITRUM
    elif chain_key == "base":
        chain_enum = Chain.BASE
    else:
        return

    targets = []
    # Bridges
    targets.extend(BRIDGES.get(chain_key, []))
    # MEV searchers (only on Ethereum)
    if chain_key == "ethereum":
        targets.extend([(a, "MEV Bot") for a in MEV_CONTRACTS])

    logger.info("=" * 60)
    logger.info("DEEP HUNTER: %s — %d targets", chain_key.upper(), len(targets))
    logger.info("=" * 60)

    all_issues = []
    for addr, name in targets:
        try:
            bal = int(str(rpc.call("eth_getBalance", [addr, "latest"])), 16) / 1e18
            code = rpc.eth_get_code(addr)
            code_len = len(str(code)) - 2 if code else 0
        except Exception:
            continue

        if code_len < 10:
            continue

        logger.info("  %s (%s): %.4f ETH, %d bytes", name, addr[:12], bal, code_len)
        issues = deep_scan_contract(rpc, explorer, addr, chain_enum, name)

        if issues:
            all_issues.append((chain_key, addr, name, bal, issues))
            for iss in issues:
                logger.warning("    %s", iss)
        else:
            logger.info("    ✅ Clean")

        time.sleep(0.5)

    if all_issues:
        with open(f"deep_hits_{chain_key}.txt", "w") as f:
            for chain, addr, name, bal, issues in all_issues:
                f.write(f"{chain} | {addr} | {name} | {bal:.4f}\n")
                for iss in issues:
                    f.write(f"  {iss}\n")
                f.write("\n")

    logger.info("Findings: %d contracts with issues", len(all_issues))


def main():
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "all"

    with open("config.toml", "rb") as f:
        config = tomllib.load(f)

    chains = ["ethereum", "polygon", "arbitrum", "base"] if target == "all" else [target]

    for chain in chains:
        url = config["rpc"].get(chain, "")
        if url:
            scan_chain(chain, url)

if __name__ == "__main__":
    main()
