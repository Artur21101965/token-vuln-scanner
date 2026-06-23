"""
UNISWAP V4 HOOK HUNTER — мониторинг Uniswap V4 хуков на уязвимости.

Стратегия:
  1. Мониторит PoolManager.Initialize события на всех цепях
  2. Извлекает адрес hook-контракта
  3. Анализирует байткод хука: selfdestruct, delegatecall, внешние вызовы, права
  4. Проверяет через Etherscan верификацию исходников
  5. Аллертит в Telegram

Цепи: Ethereum, Arbitrum, Base, Optimism, Polygon (когда V4 запустят)
Источники: Etherscan API (getLogs) + eth_getCode / eth_call
Цикл: каждые 30 минут

Usage: python v4_hook_hunter.py
"""
import sys
import os
import json
import time
import logging
import traceback
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict
from dataclasses import dataclass, field

import urllib.request
import urllib.error

CRASH_LOG = "logs/v4_hook_hunter_crash.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [V4-HOOK] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/v4_hook_hunter.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("v4-hook-hunter")
logger.setLevel(logging.INFO)

# Uniswap V4 PoolManager (CREATE2, одинаковый на всех цепях)
POOL_MANAGER = "0x000000000004444c5dc75cB358380D2e3dE08A90"

# Initialize(bytes32 indexed id, address indexed currency0, address indexed currency1, uint24 fee, int24 tickSpacing, address hooks)
INIT_EVENT_SIG = "Initialize(bytes32,address,address,uint24,int24,address)"
# topic[1] = id, topic[2] = currency0, topic[3] = currency1, data = fee,tickSpacing,hooks

# Поддерживаемые цепи (чейнид Etherscan V2)
CHAINS = {
    "ethereum":    {"id": 1,   "rpc": "https://ethereum-rpc.publicnode.com"},
    "arbitrum":    {"id": 42161, "rpc": "https://arb1.arbitrum.io/rpc"},
    "base":        {"id": 8453, "rpc": "https://mainnet.base.org"},
    "optimism":    {"id": 10,  "rpc": "https://mainnet.optimism.io"},
    "polygon":     {"id": 137, "rpc": "https://polygon-bor.publicnode.com"},
}

# Etherscan V2 API
ETHERSCAN_KEY = os.environ.get("ETHERSCAN_KEY", "")

# Опасные опкоды и сигнатуры в байткоде
DANGEROUS_OPCODES = {
    "selfdestruct": b"\xff",
    "delegatecall": b"\xf4",
    "callcode":     b"\xf2",
}

DANGEROUS_SIGS_4BYTE = {
    "approve(address,uint256)":     "095ea7b3",
    "transferOwnership(address)":   "f2fde38b",
    "renounceOwnership()":          "715018a6",
    "withdraw(uint256)":            "2e1a7d4d",
    "sweep(address)":               "16a1d7f1",
    "rescueTokens(address,address)": "10154bad",
    "transfer(address,uint256)":    "a9059cbb",
    "selfdestruct(address)":        "cb49a3e0",
}


@dataclass
class HookInfo:
    chain: str
    pool_id: str
    hook_address: str
    currency0: str
    currency1: str
    fee: int
    tx_hash: str
    created_at: str
    verified: bool = False
    source_code_similarity: float = 0.0
    risk_score: int = 0
    risk_reasons: List[str] = field(default_factory=list)


def log_crash(reason: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    os.makedirs(os.path.dirname(CRASH_LOG), exist_ok=True)
    with open(CRASH_LOG, "a") as f:
        f.write(f"[{ts}] {reason}\n{traceback.format_exc()}\n\n")


def etherscan_get_logs(chain_id: int, address: str, topic0: str, from_block: int, to_block: int) -> list:
    """Запрашивает логи через Etherscan V2 API."""
    url = (
        f"https://api.etherscan.io/v2/api"
        f"?chainid={chain_id}"
        f"&module=logs"
        f"&action=getLogs"
        f"&address={address}"
        f"&topic0={topic0}"
        f"&fromBlock={from_block}"
        f"&toBlock={to_block}"
        f"&page=1"
        f"&offset=100"
        f"&apikey={ETHERSCAN_KEY}"
    )
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        if data.get("status") == "1":
            return data.get("result", [])
        else:
            logger.debug("Etherscan logs: %s", data.get("message", ""))
            return []
    except Exception as e:
        logger.debug("Etherscan logs error: %s", e)
        return []


def etherscan_get_abi(chain_id: int, address: str) -> Optional[list]:
    """Запрашивает ABI верифицированного контракта."""
    url = (
        f"https://api.etherscan.io/v2/api"
        f"?chainid={chain_id}"
        f"&module=contract"
        f"&action=getabi"
        f"&address={address}"
        f"&apikey={ETHERSCAN_KEY}"
    )
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        if data.get("status") == "1":
            return json.loads(data["result"])
    except Exception:
        pass
    return None


def etherscan_get_source(chain_id: int, address: str) -> Optional[str]:
    """Запрашивает исходный код верифицированного контракта."""
    url = (
        f"https://api.etherscan.io/v2/api"
        f"?chainid={chain_id}"
        f"&module=contract"
        f"&action=getsourcecode"
        f"&address={address}"
        f"&apikey={ETHERSCAN_KEY}"
    )
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        if data.get("status") == "1":
            results = data.get("result", [])
            if results:
                return results[0].get("SourceCode", "")
    except Exception:
        pass
    return None


def rpc_get_code(rpc_url: str, address: str) -> str:
    """Получает байткод контракта через eth_getCode."""
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "eth_getCode",
        "params": [address, "latest"]
    }).encode()
    req = urllib.request.Request(rpc_url, payload, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        result = json.loads(r.read()).get("result", "0x")
    return result


def analyze_hook_bytecode(rpc_url: str, hook_address: str) -> tuple[int, List[str]]:
    """
    Анализирует байткод хук-контракта на уязвимости.
    Возвращает (risk_score, list[reasons]).
    """
    risk = 0
    reasons = []

    code = rpc_get_code(rpc_url, hook_address)
    if not code or code == "0x":
        return 0, ["Нет байткода (возможно EOA)"]

    code_bytes = bytes.fromhex(code[2:]) if code.startswith("0x") else bytes.fromhex(code)

    # Проверка опасных опкодов
    for name, opcode in DANGEROUS_OPCODES.items():
        if opcode in code_bytes:
            risk += 40
            reasons.append(f"Опасный опкод: {name}")

    # Проверка опасных сигнатур
    code_hex = code_bytes.hex()
    for sig_name, sig_4byte in DANGEROUS_SIGS_4BYTE.items():
        if sig_4byte in code_hex:
            risk += 15
            reasons.append(f"Сигнатура: {sig_name}")

    # Проверка: маленький контракт (менее 100 байт — прокси/пустышка)
    if len(code_bytes) < 100:
        risk += 10
        reasons.append("Очень маленький контракт (<100 байт)")

    return min(risk, 100), reasons


def analyze_hook_source(source_code: str) -> tuple[int, List[str]]:
    """
    Анализирует исходный код хука на уязвимости (если верифицирован).
    """
    risk = 0
    reasons = []

    # Уязвимые паттерны в Solidity
    vulnerable_patterns = [
        ("owner()", "имеет owner()"),
        ("onlyOwner", "модификатор onlyOwner (централизация)"),
        ("transferOwnership", "можно сменить владельца"),
        ("selfdestruct", "содержит selfdestruct"),
        ("selfDestruct", "содержит selfdestruct"),
        ("call{", "низкоуровневый call (reentrancy риск)"),
        ("delegatecall", "delegatecall (риск подмены логики)"),
        ("unchecked", "unchecked блок (переполнение)"),
        ("tx.origin", "использует tx.origin (фишинг-риск)"),
        ("block.timestamp", "зависит от block.timestamp"),
    ]

    source_lower = source_code.lower()
    for pattern, reason in vulnerable_patterns:
        if pattern.lower() in source_lower:
            risk += 10
            reasons.append(reason)

    return min(risk, 100), reasons


def parse_initialize_event(log: dict) -> Optional[HookInfo]:
    """
    Парсит Initialize событие из лога Etherscan.
    Возвращает HookInfo или None (если хуков нет).
    """
    topics = log.get("topics", [])
    data_hex = log.get("data", "0x")

    if len(topics) < 4:
        return None

    # topics[1] = pool id (bytes32)
    pool_id = topics[1] if topics[1].startswith("0x") else "0x" + topics[1]
    # topics[2] = currency0 (address, последние 20 байт)
    currency0 = "0x" + topics[2][-40:] if len(topics[2]) >= 40 else topics[2]
    # topics[3] = currency1
    currency1 = "0x" + topics[3][-40:] if len(topics[3]) >= 40 else topics[3]

    # data: fee (uint24, padded 32), tickSpacing (int24, padded 32), hooks (address, padded 32)
    data = data_hex[2:] if data_hex.startswith("0x") else data_hex
    if len(data) < 192:  # 3 × 64 hex chars
        return None

    # hooks — последние 40 hex chars данных (адрес)
    hook_hex = data[-40:]
    hook_address = "0x" + hook_hex

    if hook_address == "0x0000000000000000000000000000000000000000":
        return None  # нет хука

    # fee — первые 64 hex chars, последние 6 знаков
    fee_hex = data[56:64]
    fee = int(fee_hex, 16) if fee_hex else 0

    tx_hash = log.get("transactionHash", "")
    time_stamp = log.get("timeStamp", "")

    return HookInfo(
        chain="",
        pool_id=pool_id,
        hook_address=hook_address,
        currency0=currency0,
        currency1=currency1,
        fee=fee,
        tx_hash=tx_hash,
        created_at=time_stamp,
    )


def scan_chain(chain_name: str, chain_cfg: dict, from_block: int) -> list[HookInfo]:
    """
    Сканирует одну цепь на новые V4 пулы с хуками.
    """
    hooks_found = []
    chain_id = chain_cfg["id"]
    rpc_url = chain_cfg["rpc"]

    # Получаем текущий блок
    try:
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}).encode()
        req = urllib.request.Request(rpc_url, payload, {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            to_block = int(json.loads(r.read())["result"], 16)
    except Exception:
        logger.debug("Пропускаю %s: RPC недоступен", chain_name)
        return hooks_found

    # Проверяем что PoolManager развёрнут
    code = rpc_get_code(rpc_url, POOL_MANAGER)
    if not code or code == "0x":
        logger.debug("  %s: PoolManager не развёрнут", chain_name)
        return hooks_found

    logger.info("  %s: PoolManager есть (%d байт). Блоки: %d→%d",
                chain_name, len(code) // 2 - 1, from_block, to_block)

    # Получаем Initialize события через Etherscan
    from web3 import Web3
    init_topic = "0x" + Web3.keccak(text=INIT_EVENT_SIG).hex()

    logs = etherscan_get_logs(chain_id, POOL_MANAGER, init_topic, from_block, to_block)
    logger.info("  %s: %d Initialize событий за %d блоков", chain_name, len(logs), to_block - from_block)

    for log in logs:
        info = parse_initialize_event(log)
        if info:
            info.chain = chain_name

            # Анализ байткода
            score_bc, reasons_bc = analyze_hook_bytecode(rpc_url, info.hook_address)
            info.risk_score += score_bc
            info.risk_reasons.extend(reasons_bc)

            # Проверка верификации
            source = etherscan_get_source(chain_id, info.hook_address)
            if source and source != "Contract source code not verified":
                info.verified = True
                score_src, reasons_src = analyze_hook_source(source)
                info.risk_score += score_src
                info.risk_reasons.extend(reasons_src)

            info.risk_score = min(info.risk_score, 100)

            if info.risk_score > 0:
                hooks_found.append(info)

                logger.warning("  🪝 Hook: %s | risk=%d | %s",
                               info.hook_address[:14], info.risk_score,
                               ", ".join(info.risk_reasons[:3]))

    return hooks_found


def load_last_block() -> dict:
    """Загружает последние проверенные блоки из файла."""
    path = "v4_hook_state.json"
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_last_block(state: dict):
    with open("v4_hook_state.json", "w") as f:
        json.dump(state, f)


def run_scan():
    """Основной цикл сканирования всех цепей."""
    state = load_last_block()
    all_hooks: list[HookInfo] = []
    new_chains = 0

    for chain_name, chain_cfg in CHAINS.items():
        from_block = state.get(chain_name, 0)
        try:
            hooks = scan_chain(chain_name, chain_cfg, from_block)
            if hooks:
                all_hooks.extend(hooks)

            # Обновляем последний блок
            try:
                payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}).encode()
                req = urllib.request.Request(chain_cfg["rpc"], payload, {"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    state[chain_name] = int(json.loads(r.read())["result"], 16)
            except Exception:
                pass

            new_chains += 1
        except Exception as e:
            logger.debug("Ошибка сканирования %s: %s", chain_name, e)

    save_last_block(state)

    logger.info("Проверено цепей: %d. Хуков с рисками: %d", new_chains, len(all_hooks))

    if not all_hooks:
        logger.info("Нет хуков с уязвимостями. V4 ждёт запуска.")
        return

    # Сортируем по риску
    all_hooks.sort(key=lambda h: -h.risk_score)

    # Telegram алерт
    try:
        from src.utils import send_alert

        if all_hooks:
            top_lines = "\n".join(
                f"🪝 <b>{h.hook_address[:14]}...</b> на {h.chain}\n"
                f"  Пул: <code>{h.pool_id[:20]}...</code>\n"
                f"  Риск: {h.risk_score}/100\n"
                f"  Причины: {', '.join(h.risk_reasons[:3])}\n"
                f"  TX: <code>{h.tx_hash[:16]}...</code>"
                for h in all_hooks[:5]
            )
            send_alert(
                f"🔬 <b>Uniswap V4 HOOK HUNTER</b>\n\n"
                f"Найдено хуков с рисками: {len(all_hooks)}\n\n{top_lines}",
                "INFO"
            )

        # Запись в файл
        with open("v4_hooks_found.txt", "w") as f:
            for h in all_hooks:
                f.write(f"{h.chain} | {h.hook_address} | risk={h.risk_score} | {'; '.join(h.risk_reasons[:5])} | pool={h.pool_id} | tx={h.tx_hash}\n")

    except Exception as e:
        logger.error("Ошибка отправки алерта: %s", e)


def main():
    logger.info("=" * 50)
    logger.info("UNISWAP V4 HOOK HUNTER v1")
    logger.info("  PoolManager: %s", POOL_MANAGER)
    logger.info("  Цепи: %s", ", ".join(CHAINS.keys()))
    logger.info("  Цикл: каждые 30 минут")
    logger.info("  Статус: ожидание запуска V4")
    logger.info("=" * 50)

    while True:
        try:
            run_scan()
        except Exception as e:
            logger.error("Ошибка в run_scan: %s", e)
            log_crash(f"run_scan exception: {e}")

        logger.info("⏳ Следующий скан через 30 минут...")
        time.sleep(1800)


def run_with_restart():
    restart_delays = [10, 30, 60, 120, 300]
    crashes = 0

    while True:
        try:
            main()
        except KeyboardInterrupt:
            logger.info("Остановлен пользователем")
            break
        except SystemExit:
            break
        except Exception as e:
            crashes += 1
            delay = restart_delays[min(crashes - 1, len(restart_delays) - 1)]
            reason = f"Крах #{crashes} — {e}"
            logger.error("%s. Перезапуск через %ds...", reason, delay)
            log_crash(reason)
            time.sleep(delay)
        else:
            crashes = 0
            time.sleep(5)


if __name__ == "__main__":
    run_with_restart()
