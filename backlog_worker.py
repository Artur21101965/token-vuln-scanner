"""
BACKLOG PROCESSOR — разгребает очередь непроверенных контрактов из БД.

Стратегия:
  - Читает contract_targets WHERE status='pending' пачками по 100
  - Проверяет через MultiRpcClient (4 эндпоинта, round-robin)
  - 10 параллельных воркеров
  - Без задержек (RPC сам разруливает rate limit)
  - Обновляет статус в БД

Usage: python backlog_worker.py <chain> [--workers 10]
"""
import sys, os, time, logging, traceback, sqlite3, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BACKLOG] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("logs/backlog_worker.log", encoding="utf-8")]
)
logger = logging.getLogger("backlog-worker")

BATCH_SIZE = 100
DEFAULT_WORKERS = 20

from src.rpc import MultiRpcClient, load_rpc_urls
from src.signer import load_evm_private_key


def get_pending_contracts(chain: str, limit: int = BATCH_SIZE) -> list[tuple[str, str]]:
    """Достаёт непроверенные контракты из БД."""
    try:
        db = sqlite3.connect("scanner.db")
        rows = db.execute(
            "SELECT address, source FROM contract_targets WHERE chain=? AND status='pending' LIMIT ?",
            (chain, limit)
        ).fetchall()
        db.close()
        return rows
    except Exception as e:
        logger.error("DB error: %s", e)
        return []


def mark_checked(contracts: list[tuple[str, str]], status: str = "done", error: str = ""):
    """Обновляет статус проверенных контрактов."""
    try:
        db = sqlite3.connect("scanner.db", timeout=10)
        for addr, source in contracts:
            db.execute(
                "UPDATE contract_targets SET status=?, error=?, eth_balance=? WHERE address=?",
                (status, error, error if status == "interesting" else "0", addr)
            )
        db.commit()
        db.close()
    except Exception as e:
        logger.debug("DB update error: %s", e)


def get_balance(rpc: MultiRpcClient, addr: str) -> float:
    """Быстрая проверка баланса."""
    try:
        raw = rpc.call("eth_getBalance", [addr, "latest"])
        return int(raw, 16) / 1e18
    except Exception:
        return 0.0


def get_code_size(rpc: MultiRpcClient, addr: str) -> int:
    """Проверка размера байткода."""
    try:
        code = rpc.eth_get_code(addr)
        return len(code) // 2 - 1 if code and code != "0x" else 0
    except Exception:
        return 0


def check_contract(rpc: MultiRpcClient, addr: str, signer_addr: str = "") -> Optional[str]:
    """
    Быстрая проверка: только баланс (1 RPC-вызов).
    Возвращает строку если баланс >0.001 ETH.
    """
    bal = get_balance(rpc, addr)

    if bal >= 0.001:
        logger.info("💰 %s: баланс %.4f ETH", addr[:14], bal)
        return f"balance={bal:.4f}_eth"

    return None


def scan_batch(chain: str, addresses: list[tuple[str, str]], worker_id: int) -> int:
    """Сканирует пачку контрактов одним воркером."""
    rpc = MultiRpcClient(chain=chain, max_retries=2)

    checked = 0
    interesting = []

    for i, (addr, source) in enumerate(addresses):
        try:
            finding = check_contract(rpc, addr)
            checked += 1
            if finding:
                interesting.append((addr, source, finding))
                # Инкрементальная запись в БД
                mark_checked([(addr, source)], "interesting", finding)
        except Exception as e:
            logger.debug("Ошибка %s: %s", addr[:14], e)

        # Инкрементальная запись каждые 10 контрактов
        if i > 0 and i % 10 == 0:
            mark_checked(addresses[i-10:i], "done")

    rpc.close()

    # Маркируем оставшиеся
    mark_checked(addresses[max(0, len(addresses)-10):], "done")
    mark_checked([(a, s) for a, s, _ in interesting], "interesting")

    if checked % 50 == 0 or worker_id == 0:
        logger.info("[W%d] Проверено %d, интересных %d", worker_id, checked, len(interesting))

    return checked


def main():
    chain = sys.argv[1] if len(sys.argv) > 1 else "ethereum"
    workers = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else DEFAULT_WORKERS

    logger.info("=" * 50)
    logger.info("BACKLOG PROCESSOR — %s (%d воркеров)", chain.upper(), workers)
    logger.info("=" * 50)

    total = 0

    while True:
        addresses = get_pending_contracts(chain, BATCH_SIZE * workers)
        if not addresses:
            logger.info("Очередь пуста. Жду 60с...")
            time.sleep(60)
            continue

        logger.info("Взято %d контрактов из очереди", len(addresses))

        # Разбиваем на пачки по BATCH_SIZE для воркеров
        batches = [addresses[i:i + BATCH_SIZE] for i in range(0, len(addresses), BATCH_SIZE)]

        with ThreadPoolExecutor(max_workers=min(workers, len(batches))) as executor:
            futures = {}
            for i, batch in enumerate(batches):
                f = executor.submit(scan_batch, chain, batch, i)
                futures[f] = i

            for f in as_completed(futures):
                try:
                    n = f.result()
                    total += n
                    logger.info("Прогресс: всего %d проверено", total)
                except Exception as e:
                    logger.error("Воркер упал: %s", e)

        logger.info("Пачка завершена. Всего: %d. Следующая...", total)


if __name__ == "__main__":
    import traceback as tb
    while True:
        try:
            main()
        except KeyboardInterrupt:
            logger.info("Остановлен")
            break
        except Exception as e:
            logger.error("Крах: %s. Перезапуск через 10с...", e)
            os.makedirs("logs", exist_ok=True)
            with open("logs/backlog_worker_crash.log", "a") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {e}\n{tb.format_exc()}\n\n")
            time.sleep(10)
