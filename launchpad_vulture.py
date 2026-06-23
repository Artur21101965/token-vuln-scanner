"""
LAUNCHPAD VULTURE — finds expired locks, unlocked vesting, and abandoned launchpad funds.

Targets:
  1. Liquidity lockers with expired locks (Unicrypt, Team Finance, Mudra)
  2. Token vesting contracts — unlocked but unclaimed
  3. Launchpad factories — PinkSale, DxSale, GemPad
  4. Abandoned presale contracts with leftover funds

Usage: python launchpad_vulture.py <chain> [--drain]
"""
import tomllib
import logging
import time
import sys
from decimal import Decimal
from typing import Optional
from eth_utils import keccak

from src.rpc import RpcClient
from src.types import TokenInfo, PoolInfo, Chain, ContractTarget, Severity
from src.scanners.evm_scanner import EvmScanner
from src.data import DataCollector
from src.explorer import ExplorerClient
from src.verifiers.runner import VerifierRunner
from src.verifiers.honeypot import HoneypotVerifier
from src.verifiers.exploit_simulator import SimulatedExploitVerifier
from src.verifiers.multi_step import MultiStepVerifier
from src.exploit_executor import ExploitExecutor
from src.signer import load_evm_private_key

logging.basicConfig(level=logging.INFO, format="%(asctime)s [VULTURE] %(message)s")
logger = logging.getLogger("vulture")

CHAIN_MAP = {c.name.lower(): c for c in Chain}

# ============================================================
# Known launchpad / locker / vesting factories
# ============================================================

FACTORIES = {
    "ethereum": {
        "unicrypt_locker": "0x663A5C229c09b049E36dCc11a9B0d4a8Eb9db214",
        "team_finance_locker": "0xE2fE530C047f2d85298b07D9333C05737f1435fB",
        "team_finance_vesting": "0x36953cdBcE7344F7fd80F6a9D95e17fCB9aE5C79",
        "dxsale": "0x2B8E0A4C57EcDFe0b13a5a1a733eFe9457C8b5a4",
        "pinksale": "0x71B5759d73262FBb223956913ecF4ecC51057641",
        "sablier_vesting": "0xCD18eAa163733Da39c232722cBC4E8940b1D8888",
        "hedgey_vesting": "0x2CDE9919e81b20B4B33DD562A48a84b54C48F00C",
    },
    "polygon": {
        "unicrypt_locker": "0x663A5C229c09b049E36dCc11a9B0d4a8Eb9db214",
        "dxsale": "0x226B7D4ffED45BAa0eB9cd71bF8931F2E61DaFFE",
        "pinksale": "0x7ceCe6B0fa938e7F1dFa5A42E6085fCe1b05e1F9",
        "team_finance_vesting": "0x0e5CA5bA15B25af6839921C3B47B7c1e9dA04FEB",
    },
    "bsc": {
        "pinksale": "0x7ceCe6B0fa938e7F1dFa5A42E6085fCe1b05e1F9",
        "dxsale": "0xD9E0e7aD8B7483A52B0D99Ben5De7f86e7f5b8cB",
        "unicrypt_locker": "0x663A5C229c09b049E36dCc11a9B0d4a8Eb9db214",
    },
    "arbitrum": {
        "dxsale": "0x83c8a5eCdA5b4DDaD8f75743a465C35c1A33A4eA",
    },
    "base": {
        "pinksale": "0x5ed5dD65aB0dC1bCCC44eedAa40680D2311bbb9F",
    },
}

# Factory events
FACTORY_EVENTS = {
    "unicrypt_locker": keccak(b"onDeposit(address,address,uint256,uint256,uint256)").hex(),
    "team_finance_locker": keccak(b"LockCreated(uint256,address,address,address,uint256,uint256)").hex(),
    "pinksale": keccak(b"PresaleCreated(address,address,address,uint256,uint256)").hex(),
    "dxsale": keccak(b"PresaleCreated(address,address,address,uint256,uint256)").hex(),
}

# Unlock check selectors
UNLOCK_SELECTORS = {
    "unlockTime": "0x251c1aa3",     # unlockTime() → uint256
    "lockedUntil": "0xba3c7045",    # lockedUntil() → uint256
    "vestingEnd": "0xae450e5d",     # vestingEnd() → uint256
    "getLock": "0x1d834a1b",        # getLock(uint256) → LockInfo
    "withdrawableTokens": "0x86e0462a",  # withdrawableTokens() → uint256
    "claimable": "0xaf38d757",      # claimable(address) → uint256
    "releasable": "0xa3f8c02b",    # releasable() → uint256
}


def check_unlocked_funds(rpc: RpcClient, addr: str, signer_addr: str) -> list[str]:
    """Check if a locker/vesting contract has unlocked funds claimable by us."""
    findings = []
    for name, sel in UNLOCK_SELECTORS.items():
        try:
            result = rpc.eth_call(addr, sel, from_address=signer_addr)
            if result and result != "0x" and result != "0x" + "0" * 64:
                val = int(str(result), 16)
                if val > 0 and name in ("withdrawableTokens", "claimable", "releasable"):
                    findings.append(f"{name}: {val / 1e18:.2f} tokens withdrawable!")
                elif val > 0 and name in ("unlockTime", "lockedUntil", "vestingEnd"):
                    now = int(time.time())
                    if val <= now:
                        findings.append(f"{name}: EXPIRED (unlock was {val}, now {now}) — funds may be claimable!")
        except Exception:
            pass

    # Check native ETH balance
    try:
        raw = rpc.call("eth_getBalance", [addr, "latest"])
        bal = int(str(raw), 16) / 1e18
        if bal >= 0.001:
            findings.append(f"Native balance: {bal:.4f} ETH")
    except Exception:
        pass

    return findings


def find_lockers(chain_key: str, rpc: RpcClient, max_per_factory: int = 100):
    """Find contracts created by locker/vesting/launchpad factories."""
    chain = CHAIN_MAP.get(chain_key)
    if not chain or chain_key not in FACTORIES:
        return []

    signer = load_evm_private_key()
    signer_addr = signer.address if signer else ""
    all_findings: list[tuple[str, str, str, float]] = []

    for factory_type, factory_addr in FACTORIES[chain_key].items():
        logger.info("--- %s ---", factory_type.upper())
        
        try:
            code = rpc.eth_get_code(factory_addr)
            if not code or len(code) <= 4:
                logger.info("  Factory EOA or not deployed")
                continue
        except Exception:
            continue

        # Get recent events from factory to find child contracts
        event_topic = FACTORY_EVENTS.get(factory_type)
        if not event_topic:
            # Try to find child contracts via blockscout created-contracts instead
            try:
                from src.abi_resolver import AbiResolver
                resolver = AbiResolver()
                children = resolver.fetch_created_contracts(factory_addr, chain)
                child_addrs = children[:max_per_factory]
            except Exception:
                child_addrs = []
        else:
            try:
                current = rpc.get_block_number()
                from_block = max(0, current - 500000)
                logs = rpc.get_logs(hex(from_block), hex(current), factory_addr, ["0x" + event_topic])
                child_addrs = []
                seen = set()
                for log in logs:
                    # Extract contract address from event data/topics
                    # For lockers: created contract is often in data or topic[1]
                    topics = log.get("topics", [])
                    data = log.get("data", "")
                    # Try getting address from topics[1] (token) or topics[2] (owner)
                    for t in topics[1:]:
                        addr = "0x" + t[-40:]
                        if len(addr) == 42 and addr not in seen:
                            child_addrs.append(addr)
                            seen.add(addr)
                    # Also try data
                    for offset in range(0, len(data) - 40, 64):
                        addr = "0x" + data[offset + 24:offset + 64]
                        if len(addr) == 42 and addr != "0x" + "0" * 40 and addr not in seen:
                            child_addrs.append(addr)
                            seen.add(addr)
                    if len(child_addrs) >= max_per_factory:
                        break
            except Exception:
                child_addrs = []

        logger.info("  Found %d child contracts", len(child_addrs))

        for i, addr in enumerate(child_addrs[:max_per_factory]):
            if i % 50 == 0:
                logger.info("  Checking %d/%d...", i, len(child_addrs[:max_per_factory]))

            findings = check_unlocked_funds(rpc, addr, signer_addr)
            if findings:
                bal = 0
                try:
                    raw = rpc.call("eth_getBalance", [addr, "latest"])
                    bal = int(str(raw), 16) / 1e18
                except Exception:
                    pass
                logger.warning("  ⚠️  %s: %s (%.4f ETH)", addr[:14], ", ".join(findings[:3]), bal)
                all_findings.append((addr, factory_type, ", ".join(findings[:3]), bal))
            time.sleep(0.3)

    return all_findings


def main():
    if len(sys.argv) < 2:
        print("Usage: python launchpad_vulture.py <chain> [--drain]")
        return

    chain_key = sys.argv[1].lower()
    drain = "--drain" in sys.argv

    with open("config.toml", "rb") as f:
        config = tomllib.load(f)

    rpc_url = config["rpc"].get(chain_key, "")
    if not rpc_url:
        print(f"No RPC for {chain_key}")
        return

    rpc = RpcClient(rpc_url, max_retries=5)

    logger.info("=" * 60)
    logger.info("LAUNCHPAD VULTURE — %s", chain_key.upper())
    logger.info("=" * 60)

    findings = find_lockers(chain_key, rpc, max_per_factory=100)

    if findings:
        logger.info("=" * 60)
        logger.info("FOUND %d potentially claimable contracts:", len(findings))
        for addr, source, desc, bal in sorted(findings, key=lambda x: -x[3]):
            logger.warning("  %s | %s | %s | %.4f ETH", addr[:14], source, desc, bal)

        with open(f"vulture_{chain_key}.txt", "w") as f:
            for addr, source, desc, bal in findings:
                f.write(f"{addr} | {source} | {desc} | {bal:.4f}\n")
        logger.info("Saved to vulture_%s.txt", chain_key)
    else:
        logger.info("Nothing found — all locks/vesting properly secured or empty")


if __name__ == "__main__":
    main()
