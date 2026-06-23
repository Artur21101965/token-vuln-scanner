"""
AIRDROP HUNTER — farms testnets with confirmed airdrops for future mainnet rewards.

Active opportunities (2026):
  - Monad testnet (confirmed drop)
  - Berachain (confirmed)
  - Eclipse mainnet (just launched, possible drop)
  - Linea (potential drop)
  - Scroll (potential re-drop)

Strategy: automate interactions on testnets to qualify for airdrops.
"""
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [AIRDROP] %(message)s")
logger = logging.getLogger("airdrop")

# Current confirmed airdrops worth farming
OPPORTUNITIES = {
    "monad": {
        "status": "testnet",
        "chain": "monad-testnet",
        "actions": ["bridge", "swap", "mint_nft", "stake"],
        "rpc": "https://testnet-rpc.monad.xyz",
    },
    "berachain": {
        "status": "testnet", 
        "chain": "bera-testnet",
        "actions": ["swap", "lend", "stake"],
        "rpc": "https://artio.rpc.berachain.com",
    },
    "scroll": {
        "status": "mainnet",
        "chain": "scroll",
        "actions": ["bridge", "swap", "lend"],
        "rpc": "https://rpc.scroll.io",
    },
    "linea": {
        "status": "mainnet",
        "chain": "linea",
        "actions": ["bridge", "swap", "nft"],
        "rpc": "https://rpc.linea.build",
    },
}

ADRESSES_TO_FARM = [
    "0xD3c97D975bD035DbA2Aae2f1B8f04f3b3040A367",  # our main
]


def print_opportunities():
    """Print current airdrop farming opportunities."""
    logger.info("=" * 50)
    logger.info("CURRENT AIRDROP OPPORTUNITIES")
    logger.info("=" * 50)

    for name, info in OPPORTUNITIES.items():
        logger.info("\n%s (%s):", name.upper(), info["status"])
        logger.info("  Chain: %s", info["chain"])
        logger.info("  Actions needed: %s", ", ".join(info["actions"]))
        logger.info("  Wallet: %s", ADRESSES_TO_FARM[0])

    logger.info("\nRECOMMENDED WEEKLY ROUTINE:")
    logger.info("  Monday: Bridge ETH → %s chains", len(OPPORTUNITIES))
    logger.info("  Wednesday: Swap on each chain (small amounts)")
    logger.info("  Friday: Lend/stake on each chain")


if __name__ == "__main__":
    print_opportunities()
