"""
LIQUIDATION HUNTER — finds undercollateralized loans on Aave/Compound.

Strategy:
  1. Read all active loans from Aave/Compound
  2. Check health factor (collateral / debt)
  3. If health < 1.0 → loan is liquidatable → get 5-10% bonus
  4. For Compound: call liquidateBorrow(collateral, borrower)
  5. For Aave: call liquidationCall(collateral, debt, user)

Usage: python liquidation_hunter.py <chain> [--aggressive]
"""
import sys, tomllib, logging, time, json, urllib.request
from typing import Optional
from decimal import Decimal

from eth_utils import keccak
from src.rpc import RpcClient
from src.signer import load_evm_private_key

logging.basicConfig(level=logging.INFO, format="%(asctime)s [LIQ] %(message)s")
logger = logging.getLogger("liquidation")

CHAIN_MAP = {"ethereum": 1, "polygon": 137, "arbitrum": 42161, "base": 8453}

# Aave V3 Pool addresses
AAVE_POOLS = {
    "ethereum": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
    "polygon": "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
    "arbitrum": "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
    "base": "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5",
}

# Aave oracle addresses
AAVE_ORACLES = {
    "ethereum": "0x54586bE62E3c3580375aE3723C145253060Ca0C2",
    "polygon": "0xb023e699F5a33916Ea823A16485e259257cA8Bd1",
    "arbitrum": "0xb56c2F0B653B2e0b10C9b928C8580Ac5Df02C7C7",
    "base": "0x2Cc0Fc26eD4563A5ce5e8bdcfe1A2878676Ae156",
}

# Compound Comptroller
COMPOUND_COMPTROLLER = "0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B"

TOKEN_LIST_URL = "https://aave.com/.netlify/functions/token-list"


def get_aave_users(rpc: RpcClient, pool_addr: str, max_users: int = 50) -> list[dict]:
    """Get list of active Aave users by querying aTokens."""
    users = set()
    # Simplified: get users from aToken Transfer events
    # Better approach: query Aave subgraph (but that requires GraphQL)
    # For now: sample approach using known active positions
    known_tokens = [
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # WETH
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
        "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",  # WBTC
        "0x6B175474E89094C44Da98b954EedeAC495271d0F",  # DAI
    ]

    for token in known_tokens:
        aToken = get_aToken_address(token, "ethereum")
        if not aToken:
            continue
        try:
            # Query Transfer events to find holders
            transfer_topic = keccak(b"Transfer(address,address,uint256)").hex()
            current = rpc.get_block_number()
            logs = rpc.get_logs(hex(max(0, current - 500)), hex(current), aToken,
                                ["0x" + transfer_topic])
            for log in logs[:max_users]:
                topics = log.get("topics", [])
                if len(topics) > 1:
                    user = "0x" + topics[2][-40:]  # to address
                    if len(user) == 42:
                        users.add(user)
        except Exception:
            continue

    return [{"address": u} for u in list(users)[:max_users]]


def get_aToken_address(token: str, chain: str) -> Optional[str]:
    """Get Aave aToken address for a given underlying token."""
    atoken_map = {
        "ethereum": {
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2": "0x4d5F47FA6A74757f35C14fD3a6Ef8E3C9BC514E8",  # aWETH
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48": "0x98C23E9d8f34FEFb1B7BD6a91B7FF122F4e16F5c",  # aUSDC
            "0xdAC17F958D2ee523a2206206994597C13D831ec7": "0x23878914EFE38d27C4D67Ab83ed1b93A74D4086a",  # aUSDT
            "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599": "0x5Ee5bf7ae06D1Be5997A1A72006FE6C607eC6DE8",  # aWBTC
            "0x6B175474E89094C44Da98b954EedeAC495271d0F": "0x018008bfb33d285247A21d44E50697654f754e63",  # aDAI
        }
    }
    return atoken_map.get(chain, {}).get(token.lower())


def check_health_factor(rpc: RpcClient, pool: str, user: str) -> Optional[float]:
    """Check health factor for an Aave user."""
    # Call getUserAccountData(address) on Aave Pool
    sel = "0xbf92857c"  # getUserAccountData(address)
    calldata = sel + user[2:].lower().zfill(64)
    try:
        result = rpc.eth_call(pool, calldata)
        if not result or result == "0x":
            return None
        data = bytes.fromhex(result[2:])
        health_factor = int.from_bytes(data[168:200], "big") / 1e18
        return health_factor
    except Exception as e:
        logger.debug("Health factor error for %s: %s", user[:10], e)
        return None


def liquidate_user(rpc_url: str, pool: str, user: str, aggressive: bool):
    """Attempt to liquidate an undercollateralized position."""
    signer = load_evm_private_key()
    if not signer:
        return

    rpc = RpcClient(rpc_url, max_retries=3)
    hf = check_health_factor(rpc, pool, user)
    if not hf:
        return

    if hf >= 1.0:
        return  # Not liquidatable

    logger.warning("🚨 LIQUIDATABLE: %s | health=%.4f", user[:14], hf)

    if not aggressive:
        return

    logger.warning(">>> ATTEMPTING LIQUIDATION: %s", user[:14])
    try:
        # Build liquidation transaction
        # liquidationCall(collateral, debt, user, receiveAToken)
        liquidation_sel = "0xab9c4b5d"
        # Simplified: would need specific collateral/debt amounts
        tx_data = liquidation_sel  # placeholder

        nonce = int(str(rpc.call("eth_getTransactionCount", [signer.address, "latest"])), 16)
        gas_price = int(str(rpc.call("eth_gasPrice", [])), 16)
        chain_id = int(str(rpc.call("eth_chainId", [])), 16)

        tx = {
            "from": signer.address,
            "to": pool,
            "data": tx_data,
            "value": 0,
            "gas": 500000,
            "gasPrice": gas_price,
            "nonce": nonce,
            "chainId": chain_id,
        }
        signed = signer.sign_transaction(tx)
        raw_hex = signed.raw_transaction.hex()
        tx_hash = rpc.call("eth_sendRawTransaction", [raw_hex])
        logger.warning(">>> LIQUIDATION TX: %s", tx_hash)
    except Exception as e:
        logger.error("Liquidation failed: %s", e)


def main():
    if len(sys.argv) < 2:
        print("Usage: python liquidation_hunter.py <chain> [--aggressive]")
        return

    chain = sys.argv[1].lower()
    aggressive = "--aggressive" in sys.argv

    with open("config.toml", "rb") as f:
        config = tomllib.load(f)

    rpc_url = config["rpc"].get(chain, "")
    if not rpc_url:
        return

    pool = AAVE_POOLS.get(chain)
    if not pool:
        logger.warning("No Aave pool for %s", chain)
        return

    rpc = RpcClient(rpc_url, max_retries=3)

    logger.info("=" * 50)
    logger.info("LIQUIDATION HUNTER: %s", chain.upper())
    logger.info("Aave Pool: %s", pool[:14])
    logger.info("Aggressive: %s", aggressive)
    logger.info("=" * 50)

    # Get users with active positions
    logger.info("Fetching active users...")
    users = get_aave_users(rpc, pool, max_users=50)
    logger.info("Found %d potentially active users", len(users))

    # Check health factors
    liquidatable = []
    for i, user in enumerate(users):
        if i % 10 == 0:
            logger.info("  Checking: %d/%d...", i, len(users))
        hf = check_health_factor(rpc, pool, user["address"])
        if hf is not None:
            if hf < 1.0:
                liquidatable.append((user["address"], hf))
                logger.warning("  🚨 %s: HEALTH=%.4f — LIQUIDATABLE!", user["address"][:14], hf)
            elif hf < 1.1:
                logger.info("  ⚡ %s: HEALTH=%.4f — close to liquidation", user["address"][:14], hf)
        time.sleep(0.3)

    logger.info("=" * 50)
    logger.info("Liquidatable: %d positions", len(liquidatable))
    for user, hf in sorted(liquidatable, key=lambda x: x[1]):
        logger.warning("  %s: %.4f", user, hf)

    if aggressive and liquidatable:
        for user, hf in liquidatable[:3]:
            liquidate_user(rpc_url, pool, user, aggressive)


if __name__ == "__main__":
    main()
