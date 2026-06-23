"""
DRAIN CHECKER — проверяет контракты с деньгами на возможность вывода.

1. Берёт контракты с balance > 0.001 ETH из БД
2. Проверяет: EOA или контракт? Есть ли уязвимые функции?
3. Пробует drain если возможно

Usage: python drain_checker.py [chain]
"""
import sys, os, time, logging, json
import sqlite3
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DRAIN] %(message)s")
logger = logging.getLogger("drain-checker")

from src.rpc import MultiRpcClient
from src.signer import load_evm_private_key

# Сигнатуры drain-функций
DRAIN_SIGS = [
    ("withdraw()", "0x3ccfd60b"),
    ("withdrawAll()", "0x853828b6"),
    ("withdraw(uint256)", "0x2e1a7d4d"),
    ("sweep(address)", "0x01681a62"),
    ("emergencyWithdraw()", "0xdb2e21bc"),
    ("rescue(address)", "0x839e3201"),
    ("claim()", "0x4e71d92d"),
    ("claimTokens()", "0xe9e15b4f"),
    ("claimReward()", "0xb88a802f"),
    ("harvest()", "0x4641257d"),
    ("exit()", "0xe9fad8ee"),
    ("skim(address)", "0xbc25cf77"),
    ("sync()", "0xfff6cae9"),
    ("transfer(address,uint256)", "0xa9059cbb"),
    ("selfdestruct(address)", "0xcb49a3e0"),
]

DANGEROUS_OPCODES_SIGS = [b"\xff", b"\xf4"]  # SELFDESTRUCT, DELEGATECALL


def get_rich_contracts(chain: str, min_balance: float = 0.001) -> list[dict]:
    """Достаёт контракты с балансом из БД."""
    db = sqlite3.connect("scanner.db")
    rows = db.execute(
        "SELECT address, eth_balance, source FROM contract_targets "
        "WHERE chain=? AND status='interesting' AND error IS NOT NULL AND error != '' "
        "ORDER BY CAST(eth_balance AS REAL) DESC",
        (chain,)
    ).fetchall()
    db.close()

    if not rows:
        # Fallback: ищем по error полю (там finding string)
        db = sqlite3.connect("scanner.db")
        rows = db.execute(
            "SELECT address, error, source FROM contract_targets "
            "WHERE chain=? AND status='interesting'",
            (chain,)
        ).fetchall()
        db.close()

    results = []
    for addr, err, src in rows:
        # Парсим баланс из error строки
        bal = 0.0
        if err and "balance=" in err:
            try:
                bal = float(err.split("balance=")[1].split("_")[0])
            except: pass
        if bal >= min_balance:
            results.append({"address": addr, "balance": bal, "source": src, "error": err})
    return sorted(results, key=lambda x: -x["balance"])


def check_drainable(rpc: MultiRpcClient, addr: str, signer_addr: str) -> dict:
    """
    Проверяет контракт на drainability.
    Возвращает: {drainable: bool, method: str, reason: str, code_size: int}
    """
    result = {"drainable": False, "method": "", "reason": "", "code_size": 0}

    # 1. Байткод
    code = rpc.eth_get_code(addr)
    code_size = len(code) // 2 - 1 if code and code != "0x" else 0
    result["code_size"] = code_size

    if code_size == 0:
        result["reason"] = "EOA — не контракт"
        return result

    code_bytes = bytes.fromhex(code[2:]) if code.startswith("0x") else bytes.fromhex(code)

    # 2. Проверка опасных опкодов
    for op in DANGEROUS_OPCODES_SIGS:
        if op in code_bytes:
            op_name = "SELFDESTRUCT" if op == b"\xff" else "DELEGATECALL"
            result["reason"] = f"Опасный опкод: {op_name}"
            result["drainable"] = True
            result["method"] = "самоуничтожение / подмена кода"

    # 3. Проверка drain-сигнатур
    code_hex = code_bytes.hex()
    for sig_name, sig_4byte in DRAIN_SIGS:
        if sig_4byte in code_hex:
            result["reason"] = f"Есть функция: {sig_name}"
            result["drainable"] = True
            if not result["method"]:
                result["method"] = sig_name

    # 4. Пробуем eth_call drain-функции
    if result["drainable"]:
        for sig_name, sig_4byte in DRAIN_SIGS:
            if sig_4byte not in code_hex:
                continue
            try:
                # withdraw() — без параметров
                if sig_name in ("withdraw()", "withdrawAll()", "emergencyWithdraw()",
                                "claim()", "claimTokens()", "claimReward()",
                                "harvest()", "exit()", "skim(address)", "sync()"):
                    call_result = rpc.eth_call(addr, sig_4byte, from_address=signer_addr)
                    if call_result and call_result != "0x":
                        result["reason"] += f" | {sig_name} РАБОТАЕТ (результат: {call_result[:20]}...)"
                elif sig_name == "transfer(address,uint256)":
                    # transfer(token, amount) — нужно знать токен
                    pass
            except Exception as e:
                logger.debug("eth_call %s on %s failed: %s", sig_name, addr[:14], e)

    return result


def main():
    chain = sys.argv[1] if len(sys.argv) > 1 else "ethereum"

    rpc = MultiRpcClient(chain=chain, max_retries=3)
    signer = load_evm_private_key()
    if not signer:
        logger.error("Нет приватного ключа!")
        return
    signer_addr = signer.address

    logger.info("=" * 50)
    logger.info("DRAIN CHECKER — %s", chain.upper())
    logger.info("  Signer: %s", signer_addr)
    logger.info("=" * 50)

    contracts = get_rich_contracts(chain)
    logger.info("Контрактов с балансом: %d", len(contracts))

    if not contracts:
        logger.info("Нет контрактов с деньгами в БД. Backlog worker ещё не дошёл.")
        return

    drainable = []
    for i, c in enumerate(contracts):
        addr = c["address"]
        bal = c["balance"]
        if i % 5 == 0:
            logger.info("Проверяю %d/%d...", i, len(contracts))

        result = check_drainable(rpc, addr, signer_addr)
        result["address"] = addr
        result["balance"] = bal
        result["chain"] = chain

        if result["drainable"]:
            drainable.append(result)
            logger.warning("🚨 %s: %.4f ETH — %s (%s)",
                          addr[:14], bal, result["reason"][:80], result["method"])
        else:
            logger.info("  %s: %.4f ETH — %s", addr[:14], bal, result["reason"])

    rpc.close()

    # Сохраняем
    with open(f"drainable_{chain}.json", "w") as f:
        json.dump(drainable, f, indent=2)

    logger.info("=" * 50)
    logger.info("DRAINABLE: %d / %d", len(drainable), len(contracts))
    for d in drainable:
        logger.info("  %s: %.4f ETH — %s", d["address"][:14], d["balance"], d["reason"][:100])

    if drainable:
        from src.utils import send_alert, init_telegram
        init_telegram()
        top = drainable[:5]
        msg = "💰 <b>DRAIN CHECKER — " + chain.upper() + "</b>\n\n" + "\n".join(
            f"<code>{d['address'][:16]}...</code> — {d['balance']:.4f} ETH\n  {d['reason'][:80]}"
            for d in top
        )
        send_alert(msg, "CRITICAL")


if __name__ == "__main__":
    main()
