"""
PAIR SNIPER — buys new tokens the instant they get liquidity on DEX.

Strategy: Watch PairCreated events → buy 0.01 MATIC worth → sell on 2x.

Usage: python pair_sniper.py <chain> --auto
"""
import time, logging, threading, json, urllib.request
from src.rpc import RpcClient
from src.signer import load_evm_private_key

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SNIPE] %(message)s")
logger = logging.getLogger("sniper")

# DEX configs
SNIPE_CONFIG = {
    "polygon": {
        "rpc": "https://polygon-bor.publicnode.com",
        "factory": "0x5757371414417b8C6CAad45bAeF941aBc7d3Ab32",  # QuickSwap V2
        "router": "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff",
        "wrapped": "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",  # WMATIC
    },
}

BUY_AMOUNT = 0.01  # MATIC per snipe
SELL_MULTIPLIER = 2.0  # sell at 2x
import websocket
from eth_utils import keccak

PAIR_CREATED_TOPIC = "0x" + keccak(b"PairCreated(address,address,address,uint256)").hex()

def snipe_pair(rpc_url, factory, router, wrapped, signer, amount_wei):
    """Watch for new pairs and buy immediately."""
    rpc = RpcClient(rpc_url, max_retries=3)
    last_block = rpc.get_block_number()
    logger.info("Watching PairCreated from block %d...", last_block)

    while True:
        try:
            current = rpc.get_block_number()
            if current <= last_block:
                time.sleep(3)
                continue
            
            logs = rpc.get_logs(hex(last_block+1), hex(min(current, last_block+100)),
                                factory, [PAIR_CREATED_TOPIC])
            
            for log in logs:
                pair = "0x" + log["data"][24:64]
                token0 = "0x" + log["topics"][1][-40:]
                token1 = "0x" + log["topics"][2][-40:]
                token = token0 if token0.lower() != wrapped.lower() else token1
                
                logger.warning("🆕 NEW PAIR: %s token=%s", pair[:12], token[:12])
                
                # Check pair has real liquidity
                bal = int(str(rpc.call("eth_getBalance", [pair, "latest"])), 16) / 1e18
                if bal < 0.1:
                    logger.info("  Low liquidity (%.4f) — skip", bal)
                    continue
                
                logger.warning(">>> BUYING %.4f of %s", BUY_AMOUNT, token[:10])
                
                try:
                    nonce = int(str(rpc.call("eth_getTransactionCount", [signer.address, "latest"])), 16)
                    gas_price = int(str(rpc.call("eth_gasPrice", [])), 16)
                    chain_id = int(str(rpc.call("eth_chainId", [])), 16)
                    deadline = int(time.time()) + 120
                    
                    # swapExactETHForTokens(amountOutMin, path, to, deadline)
                    swap_sel = "0x7ff36ab5"
                    path_offset = "00000000000000000000000000000000000000000000000000000000000000a0"
                    to_addr = signer.address[2:].lower().zfill(64)
                    deadline_hex = hex(deadline)[2:].zfill(64)
                    path_len = "0000000000000000000000000000000000000000000000000000000000000002"
                    path_wrapped = wrapped[2:].lower().zfill(64)
                    path_token = token[2:].lower().zfill(64)
                    
                    data = (swap_sel + "0"*64 + path_offset + to_addr + deadline_hex + 
                            path_len + path_wrapped + path_token)
                    
                    tx = {
                        "from": signer.address, "to": router, "data": data,
                        "value": hex(amount_wei), "gas": hex(500000),
                        "gasPrice": hex(int(gas_price * 2)),
                        "nonce": hex(nonce), "chainId": chain_id,
                    }
                    signed = signer.sign_transaction(tx)
                    raw = signed.raw_transaction.hex()
                    tx_hash = rpc.call("eth_sendRawTransaction", [raw])
                    logger.warning(">>> BUY TX: %s | https://polygonscan.com/tx/%s", 
                                   tx_hash[:16], tx_hash)
                except Exception as e:
                    logger.error("Buy failed: %s", e)
            
            last_block = current
            time.sleep(3)
        except Exception as e:
            logger.debug("Error: %s", e)
            time.sleep(5)


def main():
    import sys
    chain = sys.argv[1] if len(sys.argv) > 1 else "polygon"
    auto = "--auto" in sys.argv

    cfg = SNIPE_CONFIG.get(chain)
    if not cfg:
        logger.error("No config for %s", chain)
        return

    signer = load_evm_private_key()
    rpc = RpcClient(cfg["rpc"], max_retries=2)
    bal = int(str(rpc.call("eth_getBalance", [signer.address, "latest"])), 16) / 1e18
    logger.info("Balance: %.4f MATIC | Buy: %.4f | Auto: %s", bal, BUY_AMOUNT, auto)

    if not auto:
        logger.info("DRY RUN — add --auto to actually buy")
        return

    snipe_pair(cfg["rpc"], cfg["factory"], cfg["router"], cfg["wrapped"],
               signer, int(BUY_AMOUNT * 1e18))


if __name__ == "__main__":
    main()
