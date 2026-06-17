import concurrent.futures
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional
from src.db.queue import TokenQueue, ContractQueue
from src.db.deployer_store import DeployerStore
from src.scanners.base import BaseScanner
from src.reporter.json_report import JsonReporter
from src.types import Chain, TokenInfo, PoolInfo, Finding, Severity, ContractTarget
from src.sources.blockscout import BlockscoutRecentSource
from src.monitors.slot_monitor import SlotMonitor
from src.monitors.top_token_scanner import TopTokenScanner
from src.abi_resolver import AbiResolver

logger = logging.getLogger(__name__)

RESCAN_INTERVAL_HOURS = 6


class Analyzer:
    def __init__(
        self,
        queue: TokenQueue,
        scanners: dict[Chain, BaseScanner],
        reporter: JsonReporter,
        slot_monitors: Optional[dict[Chain, SlotMonitor]] = None,
        deployer_store: Optional[DeployerStore] = None,
        top_token_scanner: Optional[TopTokenScanner] = None,
        abi_resolver: Optional[AbiResolver] = None,
        max_workers: int = 4,
    ):
        self._queue = queue
        self._scanners = scanners
        self._reporter = reporter
        self._slot_monitors = slot_monitors or {}
        self._deployer_store = deployer_store
        self._top_token_scanner = top_token_scanner
        self._abi_resolver = abi_resolver
        self._max_workers = max_workers
        self._last_rescan_check: Optional[datetime] = None

    def _get_scanner(self, chain: Chain) -> Optional[BaseScanner]:
        return self._scanners.get(chain)

    def _scan_and_report(self, token, chain, scanner) -> None:
        token_info = TokenInfo(
            address=token.token_address,
            symbol=token.symbol,
            chain=chain,
        )
        pool_info = PoolInfo(
            address=token.pair_address,
            dex=token.dex,
            liquidity_usd=token.liquidity_usd,
        )
        report = scanner.scan(token_info, pool_info)

        slot_mon = self._slot_monitors.get(chain)
        if slot_mon:
            slot_mon.record_snapshot(token.token_address)

        self._reporter.write(report)
        logger.info("Done %s — %s", token.symbol, report.summary)

        self._track_deployer(token_info, report)

    def _track_deployer(self, token_info: TokenInfo, report) -> None:
        if self._deployer_store is None:
            return
        scanner = self._get_scanner(token_info.chain)
        if scanner is None:
            return
        creator = scanner._data.get_creator_address(token_info.address, token_info.chain)
        if not creator:
            return
        has_critical = any(f.severity == Severity.CRITICAL for f in report.findings)
        self._deployer_store.add_token(creator, token_info.chain.name.lower(), has_critical=has_critical)

        if has_critical and self._abi_resolver is not None:
            self._enqueue_deployer_tokens(creator, token_info)

    def _enqueue_deployer_tokens(self, creator: str, token_info: TokenInfo) -> None:
        try:
            contracts = self._abi_resolver.fetch_created_contracts(creator, token_info.chain)
        except Exception as exc:
            logger.debug("Failed to fetch deployer contracts for %s: %s", creator, exc)
            return
        enqueued = 0
        for addr in contracts:
            if addr.lower() == token_info.address.lower():
                continue
            self._queue.add(
                chain=token_info.chain,
                token_address=addr,
                pair_address="",
                symbol="",
                liquidity_usd=Decimal("0"),
                dex="",
            )
            enqueued += 1
        if enqueued:
            logger.info("Deployer cluster: enqueued %d more tokens from %s", enqueued, creator)

    def _check_slot_changes(self):
        import sqlite3
        try:
            conn = sqlite3.connect(self._queue.db_path)
            rows = conn.execute(
                "SELECT row_id, chain, token_address, pair_address, symbol, liquidity_usd, dex "
                "FROM pending_tokens WHERE status = 'done'"
            ).fetchall()
            conn.close()
        except Exception:
            return

        for row in rows:
            try:
                chain = Chain.from_str(row[1])
            except ValueError:
                continue
            token_addr = row[2]
            slot_mon = self._slot_monitors.get(chain)
            if not slot_mon:
                continue
            try:
                changes = slot_mon.check_for_changes(token_addr)
                if changes:
                    logger.warning(
                        "Slot change on %s/%s: %s", chain.name, token_addr, changes
                    )
                    scanner = self._get_scanner(chain)
                    if not scanner:
                        continue
                    token = self._queue.get(row[0])
                    if token is None:
                        continue
                    token_info = TokenInfo(
                        address=token.token_address,
                        symbol=token.symbol,
                        chain=chain,
                    )
                    pool_info = PoolInfo(
                        address=token.pair_address,
                        dex=token.dex,
                        liquidity_usd=token.liquidity_usd,
                    )
                    report = scanner.scan(token_info, pool_info)
                    for c in changes:
                        report.findings.append(Finding(
                            check_name="slot_change_detected",
                            severity=Severity.CRITICAL,
                            description=f"{c['slot']} changed: {c['previous'][:20]}... → {c['current'][:20]}...",
                            recommendation="Verify if this change was authorized; possible rug by proxy upgrade or ownership transfer",
                        ))
                    self._reporter.write(report)
            except Exception as exc:
                logger.debug("Slot check error for %s: %s", token_addr, exc)

    def _rescan_old_tokens(self):
        now = datetime.now(timezone.utc)
        if self._last_rescan_check and now - self._last_rescan_check < timedelta(hours=RESCAN_INTERVAL_HOURS):
            return
        self._last_rescan_check = now

        import sqlite3
        try:
            conn = sqlite3.connect(self._queue.db_path)
            rows = conn.execute(
                "SELECT row_id, chain, token_address, pair_address, symbol, liquidity_usd, dex "
                "FROM pending_tokens WHERE status = 'done' "
                "ORDER BY created_at ASC"
            ).fetchall()
            conn.close()
        except Exception:
            return

        for row in rows:
            try:
                chain = Chain.from_str(row[1])
            except ValueError:
                continue
            scanner = self._get_scanner(chain)
            if not scanner:
                continue
            token = self._queue.get(row[0])
            if token is None:
                continue
            logger.info("Rescanning %s on %s", token.symbol, chain.name)
            try:
                self._scan_and_report(token, chain, scanner)
            except Exception as exc:
                logger.error("Rescan failed for %s: %s", token.symbol, exc)

    def _scan_top_tokens(self):
        if self._top_token_scanner is None:
            return
        try:
            count = self._top_token_scanner.scan()
            if count:
                logger.info("Top token scan enqueued %d new tokens", count)
            bulk = self._top_token_scanner.scan_bulk()
            if bulk:
                logger.info("Bulk scan enqueued %d EVM tokens", bulk)
            retro = self._top_token_scanner.scan_retro()
            if retro:
                logger.info("Retro scan enqueued %d EVM tokens", retro)
        except Exception as exc:
            logger.debug("Top token scan error: %s", exc)

    def _enqueue_blockscout_targets(self) -> int:
        contract_queue = ContractQueue(self._queue.db_path)
        contract_queue.init_db()
        total = 0
        for chain in Chain:
            if chain == Chain.SOLANA:
                continue
            source = BlockscoutRecentSource(max_pages=2)
            targets = source.fetch(chain)
            for t in targets:
                contract_queue.add(chain=t.chain, address=t.address, source=t.source)
                total += 1
        if total:
            logger.info("Blockscout: enqueued %d contract targets", total)
        return total

    def _scan_contract_target(self, target: ContractTarget, chain: Chain, scanner: BaseScanner) -> None:
        token_info = TokenInfo(
            address=target.address,
            symbol=target.address[:10],
            chain=chain,
        )
        pool_info = PoolInfo(
            address="",
            dex="direct",
            liquidity_usd=Decimal("0"),
        )
        report = scanner.scan(token_info, pool_info)
        self._reporter.write(report)
        logger.info("Contract scan done %s — %s", target.address[:10], report.summary)

    def process_contract_batch(self) -> int:
        contract_queue = ContractQueue(self._queue.db_path)
        contract_queue.init_db()
        targets = contract_queue.claim_next_batch(self._max_workers)
        if not targets:
            return 0

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            fut_to_target = {}
            for target in targets:
                chain = target.chain
                scanner = self._get_scanner(chain)
                if scanner is None:
                    contract_queue.mark_failed(target.row_id, error=f"No scanner for chain: {chain.name}")
                    continue
                fut = pool.submit(self._scan_contract_target, target, chain, scanner)
                fut_to_target[fut] = target

            for fut in as_completed(fut_to_target):
                target = fut_to_target[fut]
                try:
                    fut.result()
                    contract_queue.mark_done(target.row_id)
                except Exception as exc:
                    logger.error("Contract scan failed %s: %s", target.address[:10], exc)
                    contract_queue.mark_failed(target.row_id, error=str(exc))

        return len(targets)

    def process_one(self) -> bool:
        token = self._queue.claim_next()
        if token is None:
            return False

        logger.info("Analyzing %s on %s", token.symbol, token.chain.name)
        try:
            chain = token.chain
            scanner = self._get_scanner(chain)
            if scanner is None:
                self._queue.mark_failed(token.row_id, error=f"No scanner for chain: {chain.name}")
                return True

            self._scan_and_report(token, chain, scanner)
            self._queue.mark_done(token.row_id)
            return True

        except Exception as exc:
            logger.error("Failed to analyze %s: %s", token.symbol, exc)
            self._queue.mark_failed(token.row_id, error=str(exc))
            return True

    def process_batch(self) -> int:
        """Process up to max_workers tokens concurrently. Returns count of tokens processed."""
        tokens = self._queue.claim_next_batch(self._max_workers)
        if not tokens:
            return 0

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            fut_to_token = {}
            for token in tokens:
                chain = token.chain
                scanner = self._get_scanner(chain)
                if scanner is None:
                    self._queue.mark_failed(token.row_id, error=f"No scanner for chain: {chain.name}")
                    continue
                fut = pool.submit(self._scan_and_report, token, chain, scanner)
                fut_to_token[fut] = token

            for fut in as_completed(fut_to_token):
                token = fut_to_token[fut]
                try:
                    fut.result()
                    self._queue.mark_done(token.row_id)
                    logger.info("Done %s — batch worker", token.symbol)
                except Exception as exc:
                    logger.error("Failed %s: %s", token.symbol, exc)
                    self._queue.mark_failed(token.row_id, error=str(exc))

        return len(tokens)

    def run(self, interval: float = 1.0):
        logger.info("Analyzer started (max_workers=%d)", self._max_workers)
        idle_cycles = 0
        while True:
            try:
                count = self.process_batch()
                if count > 0:
                    idle_cycles = 0
                else:
                    idle_cycles += 1
                    if idle_cycles >= 10:
                        self._check_slot_changes()
                        self._rescan_old_tokens()
                        self._scan_top_tokens()
                        self._enqueue_blockscout_targets()
                        self.process_contract_batch()
                        idle_cycles = 0
                    time.sleep(interval)
            except KeyboardInterrupt:
                break
            except Exception as exc:
                logger.error("Analyzer error: %s", exc)
                time.sleep(5)
