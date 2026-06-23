"""
TESTNET AUTO-FARMER — fully automated DeFi interactions for airdrops.

Sends real transactions on testnets:
  - Wrap/unwrap native token
  - Swap on Uniswap V2 forks  
  - Approve tokens
  - Random delays to avoid Sybil detection

Usage: python testnet_farmer.py [monad|bera] --auto
"""
import random
import time
import logging
import json
import urllib.request
from eth_utils import keccak
from src.rpc import RpcClient
from src.signer import load_evm_private_key

logging.basicConfig(level=logging.INFO, format="%(asctime)s [FARM] %(message)s")
logger = logging.getLogger("farmer")

# ============================================================
# TESTNET CONFIGS — add new testnets here
# ============================================================

TESTNETS = {
    "monad": {
        "rpc": "https://testnet-rpc.monad.xyz",
        "chain_id": 10143,
        "faucet_url": "https://testnet.monad.xyz/api/faucet",
        "wrapped_native": "0x760AfE86e5de5fa0Ee542fc7B7B713e1c5425701",  # WMON
        "router": "0x...",  # Uniswap V2 fork router
        "tokens": {
            "USDC": "0x...",
            "USDT": "0x...",
        },
    },
}

# Uniswap V2 Router ABI (minimal, just the functions we need)
ROUTER_ABI = {
    "swapExactETHForTokens": "0x7ff36ab5",  # swapExactETHForTokens(uint,address[],address,uint)
    "swapExactTokensForETH": "0x18cbafe5",
    "swapExactTokensForTokens": "0x38ed1739",
}

WRAP_SELECTOR = "0xd0e30db0"  # deposit() - wrap native
APPROVE_SELECTOR = "0x095ea7b3"  # approve(address,uint256)

OUR_WALLET = "0xD3c97D975bD035DbA2Aae2f1B8f04f3b3040A367"


def claim_faucet(chain: str) -> bool:
    """Claim testnet tokens from faucet."""
    cfg = TESTNETS.get(chain)
    if not cfg:
        return False

    try:
        payload = json.dumps({"address": OUR_WALLET, "chain": chain}).encode()
        req = urllib.request.Request(cfg["faucet_url"], payload,
                                      {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        logger.info("Faucet: %s", data.get("message", "claimed"))
        return True
    except Exception as e:
        logger.warning("Faucet failed: %s — do manually", e)
        return False


def wrap_native(rpc: RpcClient, signer, amount_wei: int, wrapped_addr: str) -> str:
    """Wrap native token (e.g., MON → WMON)."""
    try:
        nonce = int(str(rpc.call("eth_getTransactionCount", [signer.address, "latest"])), 16)
        gas_price = int(str(rpc.call("eth_gasPrice", [])), 16)
        chain_id = int(str(rpc.call("eth_chainId", [])), 16)

        tx = {
            "from": signer.address,
            "to": wrapped_addr,
            "data": WRAP_SELECTOR,
            "value": hex(amount_wei),
            "gas": hex(100000),
            "gasPrice": hex(gas_price),
            "nonce": hex(nonce),
            "chainId": chain_id,
        }
        signed = signer.sign_transaction(tx)
        raw = signed.raw_transaction.hex()
        tx_hash = rpc.call("eth_sendRawTransaction", [raw])
        return str(tx_hash)
    except Exception as e:
        logger.error("Wrap failed: %s", e)
        return ""


def swap_native_for_token(rpc: RpcClient, signer, router: str, token: str, amount_wei: int) -> str:
    """Swap native token for ERC20 via Uniswap V2 router."""
    try:
        deadline = int(time.time()) + 600  # 10 minutes
        path = wrapped_native_addr + token[2:].lower().zfill(64)[:40]

        # swapExactETHForTokens(amountOutMin, path, to, deadline)
        # Pack: selector + amountOutMin(0) + offset(0x80) + to + deadline + len(path) + path[]
        data = (
            ROUTER_ABI["swapExactETHForTokens"][2:] +
            "0" * 64 +  # amountOutMin = 0 (accept any)
            "0" * 63 + "80" +  # offset to path array
            OUR_WALLET[2:].lower().zfill(64) +  # to
            hex(deadline)[2:].zfill(64) +  # deadline
            hex(2)[2:].zfill(64) +  # array length = 2
            token[2:].lower().zfill(64)  # path[0] = native (address)
            # path[1] would be next but we need wrapped native first
        )

        nonce = int(str(rpc.call("eth_getTransactionCount", [signer.address, "latest"])), 16)
        gas_price = int(str(rpc.call("eth_gasPrice", [])), 16)
        chain_id = int(str(rpc.call("eth_chainId", [])), 16)

        tx = {
            "from": signer.address,
            "to": router,
            "data": "0x" + data,
            "value": hex(amount_wei),
            "gas": hex(300000),
            "gasPrice": hex(gas_price),
            "nonce": hex(nonce),
            "chainId": chain_id,
        }
        signed = signer.sign_transaction(tx)
        raw = signed.raw_transaction.hex()
        tx_hash = rpc.call("eth_sendRawTransaction", [raw])
        return str(tx_hash)
    except Exception as e:
        logger.error("Swap failed: %s", e)
        return ""


def random_action(rpc: RpcClient, signer, chain: str, cfg: dict):
    """Execute one random DeFi action."""
    actions = ["wrap", "unwrap", "faucet"]
    # Add swap if router is configured
    if cfg.get("router") and cfg["router"] != "0x...":
        actions.append("swap")

    action = random.choice(actions)
    amount_wei = random.randint(10**14, 10**16)  # 0.0001 - 0.01 MON

    if action == "wrap":
        tx = wrap_native(rpc, signer, amount_wei, cfg["wrapped_native"])
        logger.info("  WRAP %d wei → %s", amount_wei, tx[:20] if tx else "FAIL")
    elif action == "faucet":
        claim_faucet(chain)
    elif action == "swap":
        # Swap small amount for random token
        tokens = list(cfg.get("tokens", {}).values())
        if tokens:
            token = random.choice(tokens)
            tx = swap_native_for_token(rpc, signer, cfg["router"], token, amount_wei)
            logger.info("  SWAP %d wei for %s → %s", amount_wei, token[:10], tx[:20] if tx else "FAIL")


def main():
    import sys
    chain = sys.argv[1] if len(sys.argv) > 1 else "monad"
    auto = "--auto" in sys.argv

    if not auto:
        logger.info("Dry run mode. Add --auto to send real transactions.")
        logger.info("Testnet: %s", chain)
        return

    cfg = TESTNETS.get(chain)
    if not cfg:
        logger.error("Unknown testnet: %s", chain)
        return

    signer = load_evm_private_key()
    rpc = RpcClient(cfg["rpc"], max_retries=3)

    # Check balance
    bal = int(str(rpc.call("eth_getBalance", [signer.address, "latest"])), 16) / 1e18
    logger.info("Testnet: %s | Balance: %.6f MON", chain.upper(), bal)

    if bal < 0.001:
        logger.info("Low balance — claiming faucet first...")
        claim_faucet(chain)
        time.sleep(10)

    # Start farming
    actions_per_day = random.randint(3, 7)
    logger.info("Auto-farming %d actions today", actions_per_day)

    for i in range(actions_per_day):
        random_action(rpc, signer, chain, cfg)
        delay = random.randint(120, 600)  # 2-10 minutes
        logger.info("  Next action in %d seconds...", delay)
        time.sleep(delay)

    logger.info("Daily farming done. See you tomorrow!")


if __name__ == "__main__":
    main()
